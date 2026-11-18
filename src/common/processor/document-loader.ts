/**
 * Bounded remote @context loading — port of go-credential-sdk
 * credential/common/processor/document_loader.go (go #165).
 *
 * A document under verification names its own context URLs and is
 * canonicalized before its signature is checked, so every limit here faces an
 * unauthenticated caller. One ContextBudget exists per JSON-LD operation and
 * is never shared.
 */
import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';

export type RemoteDocument = {
  contextUrl: string | null;
  document: unknown;
  documentUrl: string;
};

export const maxContextBytes = 1 << 20;
export const maxContextRequests = 16;
export const maxCachedContexts = 64;
export const maxContextLoads = 1024;
export const maxContextLoadTimeMs = 30_000;
export const maxContextBytesPerOperation = 4 << 20;
export const maxContextTerms = 10000;
export const maxInlineContextTerms = 1000;
export const maxContextTermBytes = 1 << 10;

/** Mutable so tests can shorten it (Go: contextFetchTimeout). */
export const contextLimits = { fetchTimeoutMs: 10_000 };

export class ContextLoadError extends Error {
  constructor(public readonly cause?: unknown) {
    // The cause stays off the text: it would tell the caller whether an
    // address or port answered.
    super('remote context could not be loaded');
    this.name = 'ContextLoadError';
  }
}
export class ContextAddressError extends Error {
  constructor() {
    super('context address is not public');
    this.name = 'ContextAddressError';
  }
}
export class ContextSchemeError extends Error {
  constructor() {
    super('context URL is not http or https');
    this.name = 'ContextSchemeError';
  }
}
export class ContextRequestsError extends Error {
  constructor() {
    super('context fetch made too many requests');
    this.name = 'ContextRequestsError';
  }
}
export class ContextOverflowError extends Error {
  constructor() {
    super("the operation's context budget is used up");
    this.name = 'ContextOverflowError';
  }
}
export class ContextTooLargeError extends Error {
  constructor() {
    super('context response is too large');
    this.name = 'ContextTooLargeError';
  }
}
export class ContextTimeoutError extends Error {
  constructor() {
    super('context fetch timed out');
    this.name = 'ContextTimeoutError';
  }
}
export class TooManyContextTermsError extends Error {
  constructor(limit: number) {
    super(`too many context term definitions: limit is ${limit}`);
    this.name = 'TooManyContextTermsError';
  }
}
export class ContextTermTooLongError extends Error {
  constructor() {
    super(`context term is too long: limit is ${maxContextTermBytes} bytes`);
    this.name = 'ContextTermTooLongError';
  }
}

/** errors.Is: true if `err` or anything on its cause chain is a `cls`. */
export function causedBy(err: unknown, cls: abstract new (...a: never[]) => Error): boolean {
  const seen = new Set<unknown>();
  let cur: unknown = err;
  while (cur && typeof cur === 'object' && !seen.has(cur)) {
    if (cur instanceof cls) return true;
    seen.add(cur);
    const o = cur as { cause?: unknown; details?: { cause?: unknown } };
    cur = o.cause ?? o.details?.cause;
  }
  return false;
}

// ---- public-address check ---------------------------------------------------

const nonPublic = new net.BlockList();
for (const p of [
  '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
  '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
  '192.88.99.2/32', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24',
  '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4',
]) {
  const [a, n] = p.split('/');
  nonPublic.addSubnet(a, Number(n), 'ipv4');
}
for (const p of [
  '64:ff9b:1::/48', '100::/64', '100:0:0:1::/64', '2001::/23', '2001:db8::/32',
  '3fff::/20', '5f00::/16', 'fc00::/7', 'fe80::/10', 'fec0::/10', 'ff00::/8',
]) {
  const [a, n] = p.split('/');
  nonPublic.addSubnet(a, Number(n), 'ipv6');
}

function parseIPv6(s: string): number[] | null {
  s = s.split('%')[0];
  let tail: number[] = [];
  const dot = s.lastIndexOf('.');
  if (dot >= 0) {
    const cut = s.lastIndexOf(':');
    const v4 = s.slice(cut + 1).split('.').map(Number);
    if (v4.length !== 4 || v4.some((x) => !(x >= 0 && x <= 255))) return null;
    tail = [(v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]];
    s = s.slice(0, cut + 1) + '0:0';
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const grp = (h: string) => (h === '' ? [] : h.split(':').map((x) => parseInt(x, 16)));
  const head = grp(halves[0]);
  const rest = halves.length === 2 ? grp(halves[1]) : [];
  const fill = 8 - head.length - rest.length;
  if (halves.length === 1 ? fill !== 0 : fill < 0) return null;
  const w = [...head, ...new Array(halves.length === 2 ? fill : 0).fill(0), ...rest];
  if (w.length !== 8 || w.some((x) => !(x >= 0 && x <= 0xffff))) return null;
  if (tail.length) {
    w[6] = tail[0];
    w[7] = tail[1];
  }
  return w;
}

/** An IPv6 address that carries an IPv4 address is judged by that IPv4 address. */
export function isPublicAddr(addr: string): boolean {
  const kind = net.isIP(addr.split('%')[0]);
  if (kind === 4) return !nonPublic.check(addr, 'ipv4');
  if (kind !== 6) return false;
  const w = parseIPv6(addr);
  if (!w) return false;
  const v4 = (a: number, b: number) => `${a >> 8}.${a & 255}.${b >> 8}.${b & 255}`;
  const first6Zero = w.slice(0, 6).every((x) => x === 0);
  if (w.slice(0, 5).every((x) => x === 0) && w[5] === 0xffff) return !nonPublic.check(v4(w[6], w[7]), 'ipv4');
  if (first6Zero) return !nonPublic.check(v4(w[6], w[7]), 'ipv4');
  if (w[0] === 0x64 && w[1] === 0xff9b && w.slice(2, 6).every((x) => x === 0)) {
    return !nonPublic.check(v4(w[6], w[7]), 'ipv4');
  }
  if (w[0] === 0x2002) return !nonPublic.check(v4(w[1], w[2]), 'ipv4');
  return !nonPublic.check(w.map((x) => x.toString(16)).join(':'), 'ipv6');
}

// ---- HTTP -------------------------------------------------------------------

export type HttpClient = (url: URL, signal: AbortSignal) => Promise<http.IncomingMessage>;

function guardedLookup(
  hostname: string,
  options: dns.LookupOptions,
  cb: (err: NodeJS.ErrnoException | null, address?: unknown, family?: number) => void,
): void {
  dns.lookup(hostname, { all: true }, (err, addrs) => {
    if (err) return cb(err);
    if (addrs.some((a) => !isPublicAddr(a.address))) return cb(new ContextAddressError() as never);
    if (options.all) return cb(null, addrs);
    cb(null, addrs[0].address, addrs[0].family);
  });
}

/** The default client refuses non-public addresses and ignores HTTP_PROXY. */
export function createHttpClient({ allowNonPublic = false } = {}): HttpClient {
  return (url, signal) =>
    new Promise((resolve, reject) => {
      const host = url.hostname.replace(/^\[|\]$/g, '');
      // net skips `lookup` for IP literals, so judge those here.
      if (!allowNonPublic && net.isIP(host) && !isPublicAddr(host)) {
        return reject(new ContextAddressError());
      }
      const lib = url.protocol === 'https:' ? https : http;
      const req = lib.request(url, {
        method: 'GET',
        signal,
        agent: false,
        maxHeaderSize: 64 << 10,
        headers: { accept: 'application/ld+json, application/json;q=0.9, */*;q=0.1' },
        ...(allowNonPublic ? {} : { lookup: guardedLookup as never }),
      }, resolve);
      req.on('error', reject);
      req.end();
    });
}

let httpClient: HttpClient = createHttpClient();
let cache = new Map<string, { raw: string; documentUrl: string; contextUrl: string | null }>();

/**
 * Replace the process-wide HTTP client and empty the context cache. A client
 * set here drops the public-address refusal for every fetch in the process;
 * the time, size and scheme limits still apply. null restores the default.
 */
export function setDocumentLoaderHttpClient(client: HttpClient | null): void {
  httpClient = client ?? createHttpClient();
  cache = new Map();
}

export const cacheSize = (): number => cache.size;

function isHttpUrl(u: URL): boolean {
  return u.protocol === 'http:' || u.protocol === 'https:';
}

type Link = { target: string; rel: string; type: string };
function parseLinks(header: string | string[] | undefined): Link[] {
  const text = Array.isArray(header) ? header.join(',') : header ?? '';
  const out: Link[] = [];
  for (const m of text.matchAll(/<([^>]*)>([^<]*)/g)) {
    const param = (n: string) =>
      new RegExp(`;\\s*${n}\\s*=\\s*(?:"([^"]*)"|([^;,\\s]+))`, 'i').exec(m[2]);
    const rel = param('rel');
    const type = param('type');
    out.push({
      target: m[1],
      rel: (rel?.[1] ?? rel?.[2] ?? '').toLowerCase(),
      type: type?.[1] ?? type?.[2] ?? '',
    });
  }
  return out;
}

async function readBody(res: http.IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  let n = 0;
  for await (const c of res) {
    n += (c as Buffer).length;
    if (n > maxContextBytes) {
      res.destroy();
      throw new ContextTooLargeError();
    }
    chunks.push(c as Buffer);
  }
  return Buffer.concat(chunks).toString('utf8');
}

/** One fetch: all its requests, redirects and alternates included, bounded. */
async function fetchContext(
  rawUrl: string,
): Promise<{ raw: string; documentUrl: string; contextUrl: string | null }> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new ContextSchemeError();
  }
  if (!isHttpUrl(url)) throw new ContextSchemeError();

  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(new ContextTimeoutError()), contextLimits.fetchTimeoutMs);
  try {
    for (let requests = 1; ; requests++) {
      if (requests > maxContextRequests) throw new ContextRequestsError();
      let res: http.IncomingMessage;
      try {
        res = await httpClient(url, ac.signal);
      } catch (e) {
        throw ac.signal.aborted ? ac.signal.reason : e;
      }
      const links = parseLinks(res.headers.link);
      // Alternates are followed below, past the scheme check on the first URL.
      const alternates: URL[] = [];
      for (const l of links) {
        if (l.rel === 'alternate' && l.type === 'application/ld+json') {
          let alt: URL;
          try {
            alt = new URL(l.target, url);
          } catch {
            res.destroy();
            throw new ContextSchemeError();
          }
          if (!isHttpUrl(alt)) {
            res.destroy();
            throw new ContextSchemeError();
          }
          alternates.push(alt);
        }
      }
      const status = res.statusCode ?? 0;
      const location = res.headers.location;
      if (status >= 300 && status < 400 && location) {
        res.destroy();
        try {
          url = new URL(location, url);
        } catch {
          throw new ContextSchemeError();
        }
        if (!isHttpUrl(url)) throw new ContextSchemeError();
        continue;
      }
      if (status < 200 || status >= 300) {
        res.destroy();
        throw new Error(`unexpected status ${status}`);
      }
      const ctype = String(res.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
      if (ctype !== 'application/ld+json' && alternates.length > 0) {
        res.destroy();
        url = alternates[0];
        continue;
      }
      let raw: string;
      try {
        raw = await readBody(res);
      } catch (e) {
        throw ac.signal.aborted ? ac.signal.reason : e;
      }
      let contextUrl: string | null = null;
      if (ctype !== 'application/ld+json') {
        const ctxLink = links.find((l) => l.rel === 'http://www.w3.org/ns/json-ld#context');
        if (ctxLink) contextUrl = new URL(ctxLink.target, url).toString();
      }
      return { raw, documentUrl: url.toString(), contextUrl };
    }
  } finally {
    clearTimeout(timer);
  }
}

/** Fetch (or serve from cache) a remote context; returns it with its byte size. */
async function loadRemote(rawUrl: string): Promise<{ doc: RemoteDocument; size: number }> {
  let entry = cache.get(rawUrl);
  if (!entry) {
    try {
      entry = await fetchContext(rawUrl);
      JSON.parse(entry.raw); // a non-JSON body is a failed load, and is not cached
    } catch (e) {
      throw new ContextLoadError(e);
    }
    if (cache.size >= maxCachedContexts) {
      // Evict rather than stop caching.
      cache.delete(cache.keys().next().value as string);
    }
    cache.set(rawUrl, entry);
  }
  // Every caller decodes its own copy: jsonld may mutate a context it is given.
  return {
    doc: { contextUrl: entry.contextUrl, document: JSON.parse(entry.raw), documentUrl: entry.documentUrl },
    size: Buffer.byteLength(entry.raw),
  };
}

// ---- term-definition bounds -------------------------------------------------

function expandsThrough(iri: string): string {
  const i = iri.indexOf(':');
  const prefix = i < 0 ? iri : iri.slice(0, i);
  const suffix = i < 0 ? '' : iri.slice(i + 1);
  if (iri.startsWith('@') || prefix === '_' || suffix.startsWith('//')) return '';
  return prefix;
}

const isObj = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === 'object' && !Array.isArray(v);

/**
 * Sizes the term definitions of an operation before jsonld processes them.
 * Order is ignored; every definition of every term another one expands
 * through is counted, since an IRI can use each of those at most once.
 */
export class ContextTerms {
  defs = new Map<string, string[]>();
  used = new Set<string>();
  chain = 0;
  longest = 0;

  check(limit: number): void {
    if (this.defs.size > limit) throw new TooManyContextTermsError(limit);
    if (this.longest > maxContextTermBytes || this.chain > maxContextTermBytes) {
      throw new ContextTermTooLongError();
    }
  }

  addDocument(v: unknown): void {
    if (Array.isArray(v)) {
      for (const item of v) this.addDocument(item);
    } else if (isObj(v)) {
      for (const [key, item] of Object.entries(v)) {
        if (key === '@context') this.add(item);
        else this.addDocument(item);
      }
    }
  }

  private add(ctx: unknown): void {
    if (Array.isArray(ctx)) {
      for (const item of ctx) this.add(item);
    } else if (isObj(ctx)) {
      for (const [key, def] of Object.entries(ctx)) {
        if (key === '@context') this.add(def);
        else if (key === '@vocab' || key === '@base') {
          if (typeof def === 'string') {
            this.longest = Math.max(this.longest, Buffer.byteLength(def));
            this.link(def);
          }
        } else if (!key.startsWith('@')) this.define(key, def);
      }
    }
  }

  private define(term: string, def: unknown): void {
    let iri = term; // with no IRI of its own a term is its name
    if (typeof def === 'string') iri = def;
    else if (isObj(def)) {
      if (typeof def['@id'] === 'string') iri = def['@id'];
      else if (typeof def['@reverse'] === 'string') iri = def['@reverse'];
      this.add(def['@context']);
    }
    this.longest = Math.max(this.longest, Buffer.byteLength(term), Buffer.byteLength(iri));
    const list = this.defs.get(term) ?? [];
    list.push(iri);
    this.defs.set(term, list);
    if (this.used.has(term)) this.link(iri);
    if (iri.includes(':')) this.use(expandsThrough(iri));
  }

  private use(term: string): void {
    if (this.used.has(term)) return;
    this.used.add(term);
    for (const iri of this.defs.get(term) ?? []) this.link(iri);
  }

  private link(iri: string): void {
    const term = expandsThrough(iri);
    if (term) {
      this.chain += Buffer.byteLength(iri);
      this.use(term);
    }
  }
}

// ---- per-operation budget ---------------------------------------------------

export type LocalContexts = {
  /** Local lookup (bundled/registered/injected); undefined when not local. */
  local: (url: string) => Promise<RemoteDocument | undefined> | RemoteDocument | undefined;
  /** Byte size charged for a bundled context, or undefined if not bundled. */
  bundledSize: (url: string) => number | undefined;
};

/**
 * The loader of one JSON-LD operation: bounds loads, time and bytes, and
 * holds the operation's terms. Bundled contexts include no remote context and
 * spend no load, only bytes.
 */
export class ContextBudget {
  loads = 0;
  bytes = 0;
  deadline = Date.now() + maxContextLoadTimeMs;
  terms = new ContextTerms();

  constructor(private readonly locals: LocalContexts) {}

  /** Bind for jsonld's `documentLoader` option. */
  loader = (url: string): Promise<RemoteDocument> => this.loadDocument(url);

  async loadDocument(url: string): Promise<RemoteDocument> {
    const size = this.locals.bundledSize(url);
    if (size !== undefined) {
      if ((this.bytes += size) > maxContextBytesPerOperation) throw new ContextOverflowError();
      return (await this.locals.local(url))!;
    }
    const other = await this.locals.local(url);
    if (other) return other;
    if (++this.loads > maxContextLoads || Date.now() > this.deadline) throw new ContextOverflowError();
    const { doc, size: n } = await loadRemote(url);
    if ((this.bytes += n) > maxContextBytesPerOperation) throw new ContextOverflowError();
    this.terms.addDocument(doc.document);
    this.terms.check(maxContextTerms);
    return doc;
  }

  /**
   * Puts the document's own contexts on this budget, before jsonld processes
   * them. It must be the budget's: a chain can alternate between the document
   * and remote contexts.
   */
  limitInline(doc: unknown): void {
    this.terms.addDocument(doc);
    this.terms.check(maxInlineContextTerms);
  }
}
