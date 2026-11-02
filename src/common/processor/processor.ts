/**
 * JSON-LD canonicalization (URDNA2015) — Node port of
 * credential/common/processor/processor.go
 *
 * Uses the `jsonld` library to normalize to N-Quads, then sha256 to produce
 * the digest signed by ECDSA-RDFC-2019.
 *
 * The default document loader serves a small set of W3C credential contexts
 * from disk to avoid network calls in the hot path; falls back to the
 * upstream loader for everything else.
 */
import { sha256 } from '@noble/hashes/sha256';
// eslint-disable-next-line @typescript-eslint/no-var-requires
const jsonld = require('jsonld');
// eslint-disable-next-line @typescript-eslint/no-var-requires
const rdfCanonize = require('rdf-canonize');
import w3cV2 from './w3c.credential.v2.json';
import w3cExamplesV2 from './w3c.credential.examples.v2.json';
import dataIntegrityV2 from './w3c.security.data-integrity.v2.json';
import w3cV1 from './w3c.credential.v1.json';
import securityV1 from './w3c.security.v1.json';
import securityV2 from './w3c.security.v2.json';
import secp256k1Suite from './w3c.security.secp256k1-2019.v1.json';

type RemoteDocument = {
  contextUrl: string | null;
  document: unknown;
  documentUrl: string;
};

const wellKnownContexts: Record<string, unknown> = {
  'https://www.w3.org/2018/credentials/v1': w3cV1,
  'https://www.w3.org/2018/credentials/v1.jsonld': w3cV1,
  'https://www.w3.org/ns/credentials/v2': w3cV2,
  'https://www.w3.org/ns/credentials/v2.jsonld': w3cV2,
  'https://www.w3.org/ns/credentials/examples/v2': w3cExamplesV2,
  'https://www.w3.org/ns/credentials/examples/v2.jsonld': w3cExamplesV2,
  'https://w3id.org/security/data-integrity/v2': dataIntegrityV2,
  'https://w3id.org/security/data-integrity/v2.jsonld': dataIntegrityV2,
  'https://w3id.org/security/v1': securityV1,
  'https://w3id.org/security/v2': securityV2,
  'https://w3id.org/security/suites/secp256k1-2019/v1': secp256k1Suite,
};

export type DocumentLoader = (url: string) => Promise<RemoteDocument> | RemoteDocument;

const extraContexts: Record<string, unknown> = {};
let injectedLoader: DocumentLoader | null = null;

const fallbackLoader = jsonld.documentLoaders.node({ secure: false });
const documentCache = new Map<string, RemoteDocument>();

export function registerContext(url: string, document: unknown): void {
  extraContexts[url] = document;
}

export function withDocumentLoader(loader: DocumentLoader | null): void {
  injectedLoader = loader;
}

export function bundledContextUrls(): string[] {
  return Object.keys(wellKnownContexts);
}

async function documentLoader(url: string): Promise<RemoteDocument> {
  const extra = extraContexts[url];
  if (extra) {
    return { contextUrl: null, document: extra, documentUrl: url };
  }
  const local = wellKnownContexts[url];
  if (local) {
    return { contextUrl: null, document: local, documentUrl: url };
  }
  if (injectedLoader) {
    return injectedLoader(url);
  }
  if (documentCache.has(url)) {
    return documentCache.get(url)!;
  }
  const doc = (await fallbackLoader(url)) as RemoteDocument;
  documentCache.set(url, doc);
  return doc;
}

/**
 * Canonicalize a document to URDNA2015 N-Quads, returning the bytes of the
 * sha256 digest used for ECDSA signing.
 */
export async function canonicalizeDocument(
  doc: Record<string, unknown>,
): Promise<Uint8Array> {
  if (!doc) throw new Error('failed to canonicalize document: document is nil');
  const standardized = standardizeToJSONLD(doc);

  const canonical: string = await jsonld.canonize(standardized, {
    algorithm: 'URDNA2015',
    format: 'application/n-quads',
    documentLoader,
    // Match Go json-gold behaviour: silently drop properties that don't
    // expand to an absolute IRI or keyword instead of throwing.
    safe: false,
  });

  return new Uint8Array(Buffer.from(canonical, 'utf8'));
}

export async function computeDocumentDigest(
  doc: Record<string, unknown>,
): Promise<Uint8Array> {
  const canonical = await canonicalizeDocument(doc);
  return computeDigest(canonical);
}

export function computeDigest(data: Uint8Array): Uint8Array {
  if (!data) throw new Error('failed to compute digest: input data is nil');
  return sha256(data);
}

/**
 * Apply Go's `standardizeToJSONLD` rule: numbers and booleans are wrapped in
 * a typed value object so they survive RDF conversion as strings (matches
 * the issuer-side canonicalization byte-for-byte).
 */
function standardizeToJSONLD(input: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(input)) {
    out[k] = convertToJSONLDCompatible(v);
  }
  return out;
}

function convertToJSONLDCompatible(value: unknown): unknown {
  if (value === null || value === undefined) return null;
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) {
    return value.map(convertToJSONLDCompatible);
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj)) {
      out[k] = convertToJSONLDCompatible(v);
    }
    return out;
  }
  if (typeof value === 'number') {
    return {
      '@value': numberToCanonicalString(value),
      '@type': 'http://www.w3.org/2001/XMLSchema#string',
    };
  }
  if (typeof value === 'boolean') {
    return {
      '@value': value ? 'true' : 'false',
      '@type': 'http://www.w3.org/2001/XMLSchema#boolean',
    };
  }
  // Fallback (BigInt, Symbol, …): coerce to string
  return {
    '@value': String(value),
    '@type': 'http://www.w3.org/2001/XMLSchema#string',
  };
}

function numberToCanonicalString(n: number): string {
  // Match Go's `fmt.Sprintf("%v", n)` for integers (no trailing ".0") and
  // floats (default format). JavaScript already drops trailing zeros for
  // integer-valued floats — covers 2023, 2023.5, etc.
  return String(n);
}

export function splitNQuadsKeepNL(s: string): string[] {
  return s.split(/(?<=\n)/).filter((p) => p.trim() !== '');
}

const ldOpts = { documentLoader, safe: true };

export async function expandJSONLD(doc: Record<string, unknown>): Promise<unknown[]> {
  if (!doc) throw new Error('expand: document is nil');
  const out = (await jsonld.expand(doc, ldOpts)) as unknown[];
  checkExpandedTypes(out);
  rejectRelativeIDs(out);
  return out;
}

export async function compactJSONLD(
  expanded: unknown,
  ctx: unknown,
): Promise<Record<string, unknown>> {
  return jsonld.compact(expanded, ctx, { documentLoader }) as Promise<Record<string, unknown>>;
}

export async function toRDFNQuads(doc: unknown): Promise<string[]> {
  const nq = (await jsonld.toRDF(doc, {
    ...ldOpts,
    format: 'application/n-quads',
  })) as string;
  return splitNQuadsKeepNL(nq);
}

/** Go Canonicalize: native JSON types, fail on empty / undefined terms. */
export async function canonicalizeRDF(doc: Record<string, unknown>): Promise<Uint8Array> {
  const nquads = await canonicalizeNQuads(doc);
  const canonical = Buffer.from(nquads.join(''), 'utf8');
  if (canonical.length === 0) {
    throw new Error(
      'canonicalization produced no N-Quads; the document has no @context or no JSON-LD terms',
    );
  }
  return new Uint8Array(canonical);
}

export async function canonicalizeNQuads(doc: Record<string, unknown>): Promise<string[]> {
  const [nquads] = await canonicalizeWithIdMap(doc);
  return nquads;
}

export async function canonicalizeWithIdMap(
  doc: Record<string, unknown>,
): Promise<[string[], Map<string, string>]> {
  if (!doc) throw new Error('canonicalize: document is nil');
  const dataset = await jsonld.toRDF(doc, ldOpts);
  return canonicalizeDatasetWithIdMap(dataset);
}

export async function canonicalizeNQuadsWithIdMap(
  nquads: string[],
): Promise<[string[], Map<string, string>]> {
  const dataset = rdfCanonize.NQuads.parse(nquads.join(''));
  return canonicalizeDatasetWithIdMap(dataset);
}

async function canonicalizeDatasetWithIdMap(
  dataset: unknown,
): Promise<[string[], Map<string, string>]> {
  const canonicalIdMap = new Map<string, string>();
  const nqStr: string = await rdfCanonize.canonize(dataset, {
    algorithm: 'URDNA2015',
    canonicalIdMap,
  });
  const idMap = new Map<string, string>();
  for (const [k, v] of canonicalIdMap.entries()) {
    const key = k.startsWith('_:') ? k : `_:${k}`;
    const val = String(v).startsWith('_:') ? String(v) : `_:${v}`;
    idMap.set(key, val);
  }
  return [splitNQuadsKeepNL(nqStr), idMap];
}

function isAbsoluteIri(s: string): boolean {
  return /^[A-Za-z][A-Za-z0-9+.-]*:/.test(s);
}

function relativeKeywordValues(v: unknown, keyword: string, out: string[] = []): string[] {
  if (Array.isArray(v)) {
    for (const item of v) relativeKeywordValues(item, keyword, out);
    return out;
  }
  if (v && typeof v === 'object') {
    const obj = v as Record<string, unknown>;
    for (const [k, val] of Object.entries(obj)) {
      if (k === keyword && typeof val === 'string') {
        if (val !== keyword && !val.startsWith('_:') && !isAbsoluteIri(val)) out.push(val);
      } else {
        relativeKeywordValues(val, keyword, out);
      }
    }
  }
  return out;
}

function checkExpandedTypes(expanded: unknown): void {
  const dropped = relativeKeywordValues(expanded, '@type');
  if (dropped.length > 0) {
    throw new Error(
      `json-ld: type ${JSON.stringify(dropped[0])} is not defined by @context and would be dropped, leaving it unsigned`,
    );
  }
}

function rejectRelativeIDs(expanded: unknown): void {
  const dropped = relativeKeywordValues(expanded, '@id');
  if (dropped.length > 0) {
    throw new Error(
      `json-ld: id ${JSON.stringify(dropped[0])} is not an absolute IRI and would be dropped, leaving the node unsigned`,
    );
  }
}
