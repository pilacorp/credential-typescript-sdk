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
import w3cV2 from './w3c.credential.v2.json';
import w3cExamplesV2 from './w3c.credential.examples.v2.json';

type RemoteDocument = {
  contextUrl: string | null;
  document: unknown;
  documentUrl: string;
};

const wellKnownContexts: Record<string, unknown> = {
  'https://www.w3.org/ns/credentials/v2': w3cV2,
  'https://www.w3.org/ns/credentials/v2.jsonld': w3cV2,
  'https://www.w3.org/ns/credentials/examples/v2': w3cExamplesV2,
  'https://www.w3.org/ns/credentials/examples/v2.jsonld': w3cExamplesV2,
};

const fallbackLoader = jsonld.documentLoaders.node({ secure: false });
const documentCache = new Map<string, RemoteDocument>();

async function documentLoader(url: string): Promise<RemoteDocument> {
  const local = wellKnownContexts[url];
  if (local) {
    return { contextUrl: null, document: local, documentUrl: url };
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
