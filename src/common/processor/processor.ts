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
// eslint-disable-next-line @typescript-eslint/no-var-requires
const ContextResolver = require('jsonld/lib/ContextResolver');
// eslint-disable-next-line @typescript-eslint/no-var-requires
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const URDNA2015: new (options?: { canonicalIdMap?: Map<string, string> }) => any = require('rdf-canonize/lib/URDNA2015');
import { randomUUID } from 'crypto';
import {
  ContextBudget,
  type RemoteDocument,
} from './document-loader';
import { BlankNodeWorkError, blankNodeWork, maxBlankNodeWork } from './blank-node-work';
import w3cV2 from './w3c.credential.v2.json';
import w3cExamplesV2 from './w3c.credential.examples.v2.json';
import dataIntegrityV2 from './w3c.security.data-integrity.v2.json';
import w3cV1 from './w3c.credential.v1.json';
import securityV1 from './w3c.security.v1.json';
import securityV2 from './w3c.security.v2.json';
import secp256k1Suite from './w3c.security.secp256k1-2019.v1.json';

/**
 * json-gold v0.7.0 applies a term's scoped context first and then reads the
 * term's @container and @type from the result. v2's `verifiableCredential`
 * (inside VerifiablePresentation) has `@context: null`, so Go sees neither:
 * an embedded VC lands in the default graph and a JWT string is a plain
 * literal. Dropping the two keys gives jsonld.js the same dataset.
 */
function goCompatibleV2(ctx: unknown): unknown {
  const copy = JSON.parse(JSON.stringify(ctx));
  const term = copy['@context'].VerifiablePresentation['@context'].verifiableCredential;
  delete term['@type'];
  delete term['@container'];
  return copy;
}
const w3cV2Go = goCompatibleV2(w3cV2);

const wellKnownContexts: Record<string, unknown> = {
  'https://www.w3.org/2018/credentials/v1': w3cV1,
  'https://www.w3.org/2018/credentials/v1.jsonld': w3cV1,
  'https://www.w3.org/ns/credentials/v2': w3cV2Go,
  'https://www.w3.org/ns/credentials/v2.jsonld': w3cV2Go,
  'https://www.w3.org/ns/credentials/examples/v2': w3cExamplesV2,
  'https://www.w3.org/ns/credentials/examples/v2.jsonld': w3cExamplesV2,
  'https://w3id.org/security/data-integrity/v2': dataIntegrityV2,
  'https://w3id.org/security/data-integrity/v2.jsonld': dataIntegrityV2,
  'https://w3id.org/security/v1': securityV1,
  'https://w3id.org/security/v2': securityV2,
  'https://w3id.org/security/suites/secp256k1-2019/v1': secp256k1Suite,
};

export * from './document-loader';
export { BlankNodeWorkError, blankNodeWork, maxBlankNodeWork } from './blank-node-work';

export type DocumentLoader = (url: string) => Promise<RemoteDocument> | RemoteDocument;

const extraContexts: Record<string, unknown> = {};
let injectedLoader: DocumentLoader | null = null;

export function registerContext(url: string, document: unknown): void {
  // Bundled contexts are frozen, published documents: like Go, they cannot be overridden.
  if (url in wellKnownContexts) {
    throw new Error(`registerContext: ${url} is a bundled context and cannot be overridden`);
  }
  extraContexts[url] = document;
}

export function withDocumentLoader(loader: DocumentLoader | null): void {
  injectedLoader = loader;
}

export function bundledContextUrls(): string[] {
  return Object.keys(wellKnownContexts);
}

const bundledSizes = new Map<unknown, number>();
function bundledSize(url: string): number | undefined {
  const doc = wellKnownContexts[url] ?? extraContexts[url];
  if (!doc) return undefined;
  let n = bundledSizes.get(doc);
  if (n === undefined) {
    n = Buffer.byteLength(JSON.stringify(doc));
    bundledSizes.set(doc, n);
  }
  return n;
}

/** One budget per JSON-LD operation; never shared between operations. */
function newBudget(): ContextBudget {
  return new ContextBudget({
    bundledSize,
    local: (url) => {
      const doc = wellKnownContexts[url] ?? extraContexts[url];
      if (doc) return { contextUrl: null, document: doc, documentUrl: url };
      return injectedLoader ? injectedLoader(url) : undefined;
    },
  });
}

/**
 * jsonld options for one operation. A resolver of its own keeps jsonld's
 * process-wide resolved-context cache from skipping this operation's budget.
 */
function ldOptions(budget: ContextBudget, extra: Record<string, unknown> = {}) {
  return {
    documentLoader: budget.loader,
    contextResolver: new ContextResolver({ sharedCache: new Map() }),
    ...extra,
  };
}

/** jsonld's stack overflows and type errors on hostile input become clean errors. */
async function guard<T>(op: string, fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (e) {
    if (e instanceof RangeError || e instanceof TypeError) {
      throw Object.assign(new Error(`${op}: malformed JSON-LD input`), { cause: e });
    }
    throw e;
  }
}

type Term = { termType: string; value: string; datatype?: { value: string }; language?: string };
type Quad = { subject: Term; predicate: Term; object: Term; graph: Term };

const RDF_LANGSTRING = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#langString';
const XSD_STRING = 'http://www.w3.org/2001/XMLSchema#string';
const XSD_INTEGER = 'http://www.w3.org/2001/XMLSchema#integer';
const XSD_DOUBLE = 'http://www.w3.org/2001/XMLSchema#double';
const ESCAPES: Record<string, string> = { '\\': '\\\\', '"': '\\"', '\n': '\\n', '\r': '\\r', '\t': '\\t' };

/** json-gold's escape, used for IRIs as well as literals (rdf-canonize leaves IRIs and TAB raw). */
function goEscape(s: string): string {
  return s.replace(/[\\"\n\r\t]/g, (c) => ESCAPES[c]);
}

function goTerm(t: Term): string {
  return t.termType === 'NamedNode' ? `<${goEscape(t.value)}>` : t.value;
}

/** json-gold's toNQuad. */
function goQuad(s: Term, p: Term, o: Term, g: Term): string {
  let quad = `${goTerm(s)} <${goEscape(p.value)}> `;
  if (o.termType === 'Literal') {
    quad += `"${goEscape(o.value)}"`;
    const dt = o.datatype?.value ?? XSD_STRING;
    if (dt === RDF_LANGSTRING) quad += `@${o.language ?? ''}`;
    else if (dt !== XSD_STRING) quad += `^^<${goEscape(dt)}>`;
  } else {
    quad += goTerm(o);
  }
  if (g.termType === 'NamedNode' || g.termType === 'BlankNode') quad += ` ${goTerm(g)}`;
  return quad + ' .\n';
}

/** Go compares strings by UTF-8 bytes (code points); JS sort compares UTF-16 units. */
export function compareCodePoints(a: string, b: string): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    let x = a.charCodeAt(i);
    let y = b.charCodeAt(i);
    if (x === y) continue;
    // Only a surrogate against U+E000..U+FFFF orders differently: lift surrogates above them.
    if (x >= 0xd800 && y >= 0xd800) {
      x = x >= 0xe000 ? x - 0x800 : x + 0x2000;
      y = y >= 0xe000 ? y - 0x800 : y + 0x2000;
    }
    return x - y;
  }
  return a.length - b.length;
}

/**
 * URDNA2015 that serializes and sorts N-Quads as json-gold does, both for the
 * first-degree hashes (which pick the blank node labels) and for the output.
 */
class GoURDNA2015 extends URDNA2015 {
  async hashFirstDegreeQuads(id: string): Promise<string> {
    const info = this.blankNodeInfo.get(id);
    const nquads = Array.from(info.quads as Iterable<Quad>, (q) =>
      goQuad(
        this.modifyFirstDegreeComponent(id, q.subject, 'subject'),
        q.predicate,
        this.modifyFirstDegreeComponent(id, q.object, 'object'),
        this.modifyFirstDegreeComponent(id, q.graph, 'graph'),
      ),
    );
    nquads.sort(compareCodePoints);
    const md = this.createMessageDigest();
    for (const nquad of nquads) md.update(nquad);
    info.hash = await md.digest();
    return info.hash;
  }

  async main(dataset: Quad[]): Promise<string> {
    await super.main(dataset); // assigns the canonical labels; its output uses rdf-canonize's serializer
    const lines = (this.quads as Quad[]).map((q) =>
      goQuad(
        this._componentWithCanonicalId(q.subject),
        q.predicate,
        this._componentWithCanonicalId(q.object),
        this._componentWithCanonicalId(q.graph),
      ),
    );
    return lines.sort(compareCodePoints).join('');
  }
}

/** The one call into URDNA2015, refusing a dataset that would take it factorial time. */
async function normalizeDataset(
  dataset: unknown,
  canonicalIdMap?: Map<string, string>,
): Promise<string> {
  const quads = Array.isArray(dataset) ? dataset : rdfCanonize.NQuads.legacyDatasetToQuads(dataset);
  if (blankNodeWork(quads) > maxBlankNodeWork) {
    throw new BlankNodeWorkError();
  }
  return new GoURDNA2015({ canonicalIdMap }).main(quads);
}

const INT64 = 2 ** 63;

/** json-gold's GetCanonicalDouble: %1.15E with trailing mantissa and leading exponent zeros removed. */
function goDouble(n: number): string {
  return n.toExponential(15).replace(/(\d)0*e\+?(-)?0*(\d)/, '$1E$2$3');
}

/**
 * json-gold types a native number as xsd:integer only when it is integral and
 * fits int64, otherwise as xsd:double. jsonld.js instead looks for a '.' in
 * String(n), so 1e-7 became "0"^^xsd:integer (and stayed "0" when changed to
 * 9e-7) and 2^63..1e21 stayed integers. Writes Go's lexical form into each
 * value object of an expanded document.
 */
function goNumbers(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(goNumbers);
  if (!v || typeof v !== 'object') return v;
  const o = v as Record<string, unknown>;
  if ('@value' in o) {
    const n = o['@value'];
    const type = o['@type'] as string | undefined;
    if (typeof n !== 'number' || type === '@json') return o;
    const integral = Number.isInteger(n) && n >= -INT64 && n < INT64 && type !== XSD_DOUBLE;
    return {
      ...o,
      '@value': integral ? BigInt(n).toString() : goDouble(n),
      '@type': type ?? (integral ? XSD_INTEGER : XSD_DOUBLE),
    };
  }
  return Object.fromEntries(Object.entries(o).map(([k, x]) => [k, goNumbers(x)]));
}

/**
 * Keys jsonld.js cannot carry into the dataset. It skips an own `__proto__`
 * even in safe mode, so a claim added under that name after signing went
 * unsigned; refuse it. An empty key maps to the bare @vocab IRI in jsonld.js
 * while json-gold drops it: refuse on the strict path, drop on the legacy one.
 */
function checkKeys(v: unknown, dropEmpty: boolean): unknown {
  if (Array.isArray(v)) return v.map((x) => checkKeys(x, dropEmpty));
  if (!v || typeof v !== 'object') return v;
  const out: Record<string, unknown> = {};
  for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
    if (k === '__proto__') throw new Error('json-ld: a "__proto__" key cannot be canonicalized');
    if (k === '@context') {
      out[k] = x;
      continue;
    }
    if (k === '') {
      if (dropEmpty) continue;
      throw new Error('json-ld: an empty key would be dropped, leaving it unsigned');
    }
    out[k] = checkKeys(x, dropEmpty);
  }
  return out;
}

/**
 * jsonld.js 8.3.3 merges an @import target together with its {"@context": …}
 * wrapper and then refuses the "@context" key, while json-gold imports it.
 * Resolve @import in the document's own contexts first; local definitions win
 * over imported ones (JSON-LD 1.1 §4.1.2).
 */
async function inlineImports(v: unknown, budget: ContextBudget): Promise<unknown> {
  if (Array.isArray(v)) return Promise.all(v.map((x) => inlineImports(x, budget)));
  if (!v || typeof v !== 'object') return v;
  const out: Record<string, unknown> = {};
  for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
    out[k] = k === '@context' ? await importContexts(x, budget) : await inlineImports(x, budget);
  }
  return out;
}

async function importContexts(ctx: unknown, budget: ContextBudget): Promise<unknown> {
  if (Array.isArray(ctx)) return Promise.all(ctx.map((c) => importContexts(c, budget)));
  if (!ctx || typeof ctx !== 'object' || !('@import' in ctx)) return ctx;
  const { '@import': url, ...local } = ctx as Record<string, unknown>;
  if (typeof url !== 'string') throw new Error('json-ld: @import must be a string');
  const remote = (await budget.loader(url)).document as Record<string, unknown> | null;
  const imported = remote?.['@context'];
  if (!imported || typeof imported !== 'object' || Array.isArray(imported) || '@import' in imported) {
    throw new Error('json-ld: @import must reference a single context that has no @import');
  }
  return { ...imported, ...local };
}

/** jsonld.js's absolute-IRI test: anything else is dropped from the dataset. */
const isJsonldAbsolute = (s: string) => /^([A-Za-z][A-Za-z0-9+-.]*|_):[^\s]*$/.test(s);

/**
 * json-gold keeps a relative @type as `<Type>`; jsonld.js drops it. Swap each
 * one for a unique absolute IRI before toRDF and put the original back after.
 */
function holdRelativeTypes(expanded: unknown): [unknown, (dataset: Quad[]) => Quad[]] {
  const tag = `urn:uuid:${randomUUID()}#`;
  const held: string[] = [];
  const walk = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(walk);
    if (!v || typeof v !== 'object') return v;
    const o = v as Record<string, unknown>;
    if ('@value' in o) return o;
    return Object.fromEntries(
      Object.entries(o).map(([k, x]) => {
        if (k === '@type' && Array.isArray(x)) {
          return [k, x.map((t) => (typeof t === 'string' && !isJsonldAbsolute(t) ? tag + (held.push(t) - 1) : t))];
        }
        return [k, walk(x)];
      }),
    );
  };
  const out = walk(expanded);
  const restore = (dataset: Quad[]) => {
    for (const q of dataset) {
      if (q.object.termType === 'NamedNode' && q.object.value.startsWith(tag)) {
        q.object = { ...q.object, value: held[Number(q.object.value.slice(tag.length))] };
      }
    }
    return dataset;
  };
  return [out, restore];
}

/**
 * Canonicalize a document to URDNA2015 N-Quads, returning the bytes of the
 * sha256 digest used for ECDSA signing.
 */
export async function canonicalizeDocument(
  doc: Record<string, unknown>,
): Promise<Uint8Array> {
  if (!doc) throw new Error('failed to canonicalize document: document is nil');
  const budget = newBudget();

  // The two steps of jsonld.canonize, which cannot stop between them to check
  // the cost. Like Go, this leaves safe mode off: properties that don't expand
  // to an absolute IRI or keyword are silently dropped (legacy semantics).
  const canonical = await guard('failed to normalize document', async () => {
    const standardized = standardizeToJSONLD(checkKeys(doc, true) as Record<string, unknown>);
    budget.limitInline(standardized);
    const expanded = await jsonld.expand(await inlineImports(standardized, budget), ldOptions(budget, { safe: false }));
    const [held, restore] = holdRelativeTypes(expanded);
    const dataset = await jsonld.toRDF(held, ldOptions(budget, { safe: false }));
    return normalizeDataset(restore(dataset));
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

/**
 * Go's `fmt.Sprintf("%v", float64)`: shortest round-trip digits, in exponent
 * form (`1e+06`, `1.7e+09`, `1e-05`) when the decimal exponent is < -4 or >= 6.
 * Only the legacy canonicalizer uses this; the library path keeps native types.
 */
function numberToCanonicalString(n: number): string {
  if (n === 0) return Object.is(n, -0) ? '-0' : '0';
  if (!Number.isFinite(n)) return String(n);
  const [mant, exp] = n.toExponential().split('e');
  const e = Number(exp);
  if (e < -4 || e >= 6) {
    return `${mant}e${e < 0 ? '-' : '+'}${String(Math.abs(e)).padStart(2, '0')}`;
  }
  return String(n);
}

export function splitNQuadsKeepNL(s: string): string[] {
  return s.split(/(?<=\n)/).filter((p) => p.trim() !== '');
}


export async function expandJSONLD(doc: Record<string, unknown>): Promise<unknown[]> {
  if (!doc) throw new Error('expand: document is nil');
  const budget = newBudget();
  const out = await guard('expand', async () => {
    checkKeys(doc, false);
    budget.limitInline(doc);
    return (await jsonld.expand(await inlineImports(doc, budget), ldOptions(budget, { safe: true }))) as unknown[];
  });
  checkExpandedTypes(out);
  rejectRelativeIDs(out);
  return out;
}

export async function compactJSONLD(
  expanded: unknown,
  ctx: unknown,
): Promise<Record<string, unknown>> {
  const budget = newBudget();
  return guard('compact', async () =>
    jsonld.compact(expanded, await importContexts(ctx, budget), ldOptions(budget, { safe: true })),
  );
}

export async function toRDFNQuads(doc: unknown): Promise<string[]> {
  const budget = newBudget();
  const nq = await guard('to rdf', async () => {
    checkKeys(doc, false);
    budget.limitInline(doc);
    const expanded = await jsonld.expand(await inlineImports(doc, budget), ldOptions(budget, { safe: true }));
    return (await jsonld.toRDF(
      goNumbers(expanded),
      ldOptions(budget, { safe: true, format: 'application/n-quads' }),
    )) as string;
  });
  return splitNQuadsKeepNL(nq.replace(/\t/g, '\\t'));
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
  // Like Go's toRDFDataset: expand first so dropped types / relative ids are
  // refused, then convert the expanded form (no contexts left to load).
  const expanded = await expandJSONLD(doc);
  const dataset = await guard('canonicalize', () =>
    jsonld.toRDF(goNumbers(expanded), ldOptions(newBudget(), { safe: true })),
  );
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
  const nqStr = await normalizeDataset(dataset, canonicalIdMap);
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

// json-gold's IsKeyword: a keyword value (e.g. `@type: "@json"`) is never relative.
const KEYWORDS = new Set(
  ('@base @container @context @default @direction @embed @explicit @json @id @included @index @first ' +
    '@graph @import @language @list @nest @none @omitDefault @prefix @preserve @propagate @protected ' +
    '@requireAll @reverse @set @type @value @version @vocab').split(' '),
);

// Go: ld.Arrayify(val) then IsRelativeIri on every string, so array-valued @type counts.
export function relativeKeywordValues(v: unknown, keyword: string, out: string[] = []): string[] {
  if (Array.isArray(v)) {
    for (const item of v) relativeKeywordValues(item, keyword, out);
    return out;
  }
  if (v && typeof v === 'object') {
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
      if (k !== keyword) {
        relativeKeywordValues(val, keyword, out);
        continue;
      }
      for (const x of Array.isArray(val) ? val : [val]) {
        if (typeof x === 'string' && !KEYWORDS.has(x) && !x.startsWith('_:') && !isAbsoluteIri(x)) {
          out.push(x);
        }
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
