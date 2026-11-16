import { createHash } from 'node:crypto';
import { checkOriginEntry, newOriginList, redirectsAny, redirectsTo, type Redirects } from './internal/allowlist';
import { cachedGet } from './internal/httpcache';
import { checkIntegrityBytes, wellFormedIntegrity } from './internal/sri';
import { httpsURL, parseURL } from './internal/url';
import { validURI } from './internal/uri';
import type { Limits } from './internal/safehttp';
import { StatusError } from './internal/safehttp';
import { hasOwn } from '../common/util/json';

export const ErrNotFound = Object.assign(new Error('typemeta: no Type Metadata for the type'), { name: 'TypeMetaError' });
export const ErrInvalid = Object.assign(new Error('typemeta: Type Metadata document is invalid'), { name: 'TypeMetaError' });
export const ErrClaims = Object.assign(new Error('typemeta: claim metadata is invalid'), { name: 'TypeMetaError' });
export const ErrCycle = Object.assign(new Error('typemeta: extends cycle'), { name: 'TypeMetaError' });
export const ErrViolated = Object.assign(new Error('typemeta: payload violates the claim metadata'), {
  name: 'TypeMetaError',
});

export {
  ErrAddressBlocked,
  ErrBodyTooLarge,
  ErrContentTypeNotAccepted,
  ErrNotFollowed as ErrRedirectNotAllowed,
  ErrRedirectTargetNotAllowed,
  ErrTooManyRedirects,
  StatusError,
} from './internal/safehttp';

const maxDocumentBytes = 256 << 10;
const maxChain = 8;
const maxClaims = 1000;
const maxPath = 64;

export interface Ref {
  vct: string;
  integrity?: string;
}

export interface Resolver {
  metadata(ref: Ref, signal?: AbortSignal): Promise<Buffer>;
}

export type PathEl = string | number | null;

export interface Claim {
  path: PathEl[];
  display?: { locale?: string; label?: string; description?: string }[];
  mandatory?: boolean;
  sd?: string;
  svgId?: string;
}

export interface Display {
  locale?: string;
  name?: string;
  description?: string;
}

export class Metadata {
  constructor(
    readonly vct: string,
    readonly chain: string[],
    readonly name: string,
    readonly description: string,
    readonly display: Display[],
    readonly claims: Claim[],
    readonly documents: Buffer[],
  ) {}

  validateClaims(
    claims: Record<string, unknown>,
    opts: { allDisclosures?: boolean; issued?: Record<string, unknown> } = {},
  ): void {
    for (const [i, c] of this.claims.entries()) {
      try {
        checkClaim(c, fromIssued(opts.issued ?? claims, claims), Boolean(opts.allDisclosures));
      } catch (err) {
        throw Object.assign(
          new Error(`typemeta: claims[${i}] with path ${JSON.stringify(c.path)}: ${(err as Error).message}`),
          { cause: ErrViolated },
        );
      }
    }
  }
}

export function integrity(doc: Uint8Array | Buffer | string): string {
  const b = typeof doc === 'string' ? Buffer.from(doc) : Buffer.from(doc);
  return `sha256-${createHash('sha256').update(b).digest('base64')}`;
}

export function checkIntegrity(data: Uint8Array | Buffer, value: string): void {
  try {
    checkIntegrityBytes(Buffer.from(data), value);
  } catch (err) {
    throw Object.assign(new Error(`typemeta: ${(err as Error).message}`), { cause: ErrInvalid });
  }
}

export function wellFormed(value: string): boolean {
  return wellFormedIntegrity(value);
}

export function staticResolver(...docs: Array<Buffer | string | Uint8Array>): Resolver {
  if (!docs.length) throw new Error('typemeta: Static needs at least one document');
  const map = new Map<string, Buffer>();
  docs.forEach((d, i) => {
    const b = Buffer.from(typeof d === 'string' ? d : d);
    const obj = JSON.parse(b.toString('utf8')) as { vct?: unknown };
    if (typeof obj.vct !== 'string' || !obj.vct) {
      throw new Error(`typemeta: Static document ${i} is not a JSON object with a non-empty string vct`);
    }
    if (map.has(obj.vct)) throw new Error(`typemeta: Static document ${i} has the vct of an earlier one`);
    map.set(obj.vct, b);
  });
  return {
    async metadata(ref) {
      const d = map.get(ref.vct);
      if (!d) throw Object.assign(new Error('typemeta: no preloaded document for the vct'), { cause: ErrNotFound });
      return Buffer.from(d);
    },
  };
}

interface rawDoc {
  vct: string;
  name: string;
  description: string;
  extends?: string;
  extendsIntegrity?: string;
  display?: Display[];
  claims?: unknown;
}

export async function load(r: Resolver, ref: Ref, signal?: AbortSignal): Promise<Metadata> {
  if (!ref.vct) throw new Error('typemeta: Load of an empty vct');
  const docs: rawDoc[] = [];
  const raws: Buffer[] = [];
  const seen = new Set<string>();
  let next = ref;
  for (;;) {
    const raw = await r.metadata(next, signal);
    if (raw.length > maxDocumentBytes) {
      throw Object.assign(new Error(`typemeta: document ${docs.length} of the chain is over ${maxDocumentBytes} bytes`), {
        cause: ErrInvalid,
      });
    }
    if (next.integrity) checkIntegrity(raw, next.integrity);
    const d = readDocument(raw);
    if (d.vct !== next.vct) {
      throw Object.assign(
        new Error(`typemeta: document ${docs.length} of the chain has a vct other than the type that led to it`),
        { cause: ErrInvalid },
      );
    }
    docs.push(d);
    raws.push(Buffer.from(raw));
    seen.add(d.vct);
    if (!d.extends) break;
    if (seen.has(d.extends)) {
      throw Object.assign(new Error('typemeta: extends cycle'), { cause: ErrCycle });
    }
    if (docs.length === maxChain) {
      throw Object.assign(new Error(`typemeta: the extends chain is over ${maxChain} documents`), { cause: ErrInvalid });
    }
    next = { vct: d.extends, integrity: d.extendsIntegrity };
  }

  let display: Display[] = [];
  let merged: Claim[] = [];
  const chain: string[] = [];
  for (let i = docs.length - 1; i >= 0; i--) {
    chain.push(docs[i].vct);
    if (docs[i].display?.length) display = docs[i].display!;
    const claims = readClaims(docs[i]);
    merged = mergeClaims(merged, claims);
  }
  chain.reverse();
  return new Metadata(ref.vct, chain, docs[0].name, docs[0].description, display, merged, raws);
}

function readDocument(raw: Buffer): rawDoc {
  const obj = JSON.parse(raw.toString('utf8')) as Record<string, unknown>;
  if (typeof obj !== 'object' || obj === null) {
    throw Object.assign(new Error('typemeta: document is not a JSON object'), { cause: ErrInvalid });
  }
  if (typeof obj.vct !== 'string' || !obj.vct) {
    throw Object.assign(new Error('typemeta: document has no non-empty string vct'), { cause: ErrInvalid });
  }
  for (const k of Object.keys(obj)) {
    if (k.endsWith('#integrity') && typeof obj[k] === 'string' && obj[k] && !wellFormedIntegrity(obj[k] as string)) {
      throw Object.assign(new Error(`typemeta: ${k} is not integrity metadata`), { cause: ErrInvalid });
    }
  }
  return {
    vct: obj.vct,
    name: typeof obj.name === 'string' ? obj.name : '',
    description: typeof obj.description === 'string' ? obj.description : '',
    extends: typeof obj.extends === 'string' ? obj.extends : undefined,
    extendsIntegrity: typeof obj['extends#integrity'] === 'string' ? (obj['extends#integrity'] as string) : undefined,
    display: Array.isArray(obj.display) ? (obj.display as Display[]) : undefined,
    claims: obj.claims,
  };
}

function readClaims(d: rawDoc): Claim[] {
  if (d.claims === undefined) return [];
  if (!Array.isArray(d.claims)) {
    throw Object.assign(new Error('typemeta: claims is not an array'), { cause: ErrClaims });
  }
  if (d.claims.length > maxClaims) {
    throw Object.assign(new Error('typemeta: too many claims'), { cause: ErrClaims });
  }
  return d.claims.map((c, i) => {
    if (typeof c !== 'object' || c === null) throw Object.assign(new Error(`claims[${i}] is not an object`), { cause: ErrClaims });
    const rec = c as Record<string, unknown>;
    if (!Array.isArray(rec.path) || rec.path.length === 0 || rec.path.length > maxPath) {
      throw Object.assign(new Error(`claims[${i}] has an invalid path`), { cause: ErrClaims });
    }
    const path = rec.path.map((el) => {
      if (el === null || typeof el === 'string' || (typeof el === 'number' && Number.isInteger(el) && el >= 0)) {
        return el as PathEl;
      }
      throw Object.assign(new Error(`claims[${i}] path element is invalid`), { cause: ErrClaims });
    });
    const sd = typeof rec.sd === 'string' ? rec.sd : 'allowed';
    if (sd !== 'always' && sd !== 'allowed' && sd !== 'never') {
      throw Object.assign(new Error(`claims[${i}] sd is invalid`), { cause: ErrClaims });
    }
    return {
      path,
      display: rec.display as Claim['display'],
      mandatory: Boolean(rec.mandatory),
      sd,
      svgId: typeof rec.svg_id === 'string' ? rec.svg_id : undefined,
    };
  });
}

function pathKey(path: PathEl[]): string {
  return path
    .map((el) => {
      if (typeof el === 'string') return `s${el.length}:${el}`;
      if (el === null) return 'n';
      return `i${el};`;
    })
    .join('');
}

function mergeClaims(inherited: Claim[], child: Claim[]): Claim[] {
  const out = inherited.map((c) => ({ ...c, path: [...c.path] }));
  const byPath = new Map<string, number[]>();
  out.forEach((p, j) => {
    const k = pathKey(p.path);
    byPath.set(k, [...(byPath.get(k) ?? []), j]);
  });
  for (const c of child) {
    const matches = byPath.get(pathKey(c.path)) ?? [];
    for (const j of matches) {
      const p = out[j];
      if (c.sd && p.sd && p.sd !== 'allowed' && c.sd !== p.sd) {
        throw Object.assign(new Error(`claim changes an inherited sd of ${p.sd}`), { cause: ErrClaims });
      }
      if (c.sd) p.sd = c.sd;
      if (p.mandatory && c.mandatory === false) {
        throw Object.assign(new Error('claim changes an inherited mandatory true to false'), { cause: ErrClaims });
      }
      if (c.mandatory) p.mandatory = true;
      if (c.display) p.display = c.display;
      if (c.svgId) p.svgId = c.svgId;
    }
    if (!matches.length) out.push(c);
  }
  return out;
}

interface IssuedNode {
  disclosed: boolean;
  hidden: boolean;
  hiddenFields: number;
  fields?: Record<string, IssuedNode>;
  elems?: IssuedNode[];
}

function isPlaceholder(v: unknown): boolean {
  return Boolean(
    v &&
      typeof v === 'object' &&
      !Array.isArray(v) &&
      Object.keys(v as object).length === 1 &&
      hasOwn(v as object, '...'),
  );
}

function fromIssued(issued: unknown, rec: unknown, disclosed = false): IssuedNode {
  if (isPlaceholder(issued)) {
    if (isPlaceholder(rec) || rec === undefined) {
      return { disclosed: false, hidden: true, hiddenFields: 0 };
    }
    return fromIssued(rec, rec, true);
  }
  if (Array.isArray(issued)) {
    const recArr = Array.isArray(rec) ? rec : [];
    return {
      disclosed,
      hidden: false,
      hiddenFields: 0,
      elems: issued.map((e, i) => fromIssued(e, recArr[i])),
    };
  }
  if (issued && typeof issued === 'object') {
    const recObj =
      rec && typeof rec === 'object' && !Array.isArray(rec) ? (rec as Record<string, unknown>) : {};
    const src = issued as Record<string, unknown>;
    const fields: Record<string, IssuedNode> = {};
    for (const k of Object.keys(src)) {
      if (k === '_sd' || k === '_sd_alg') continue;
      fields[k] = fromIssued(src[k], recObj[k]);
    }
    let opened = 0;
    for (const k of Object.keys(recObj)) {
      if (k === '_sd' || k === '_sd_alg' || hasOwn(src, k)) continue;
      fields[k] = fromIssued(recObj[k], recObj[k], true);
      opened++;
    }
    const sd = src._sd;
    const nSd = Array.isArray(sd) ? sd.length : 0;
    return {
      disclosed,
      hidden: false,
      hiddenFields: Math.max(0, nSd - opened),
      fields,
    };
  }
  return { disclosed, hidden: false, hiddenFields: 0 };
}

function elemsOf(n: IssuedNode, all: boolean): IssuedNode[] {
  const list = n.elems ?? [];
  return all ? list.filter((e) => !e.hidden) : list;
}

function checkClaim(c: Claim, root: IssuedNode, all: boolean): void {
  let sel: IssuedNode[] = [root];
  for (const el of c.path) {
    const next: IssuedNode[] = [];
    for (const n of sel) {
      if (n.hidden) continue;
      if (typeof el === 'string') {
        if (!n.fields) {
          throw new Error('a key is selected in a value that is not an object (§5.6.1.2)');
        }
        if (!hasOwn(n.fields, el)) {
          if (c.mandatory && (all || n.hiddenFields === 0)) {
            throw new Error('a mandatory claim is not in the credential (§5.6.3)');
          }
          continue;
        }
        next.push(n.fields[el]);
      } else if (el === null) {
        if (!n.elems) throw new Error('every element is selected in a value that is not an array (§5.6.1.2)');
        next.push(...elemsOf(n, all));
      } else {
        if (!n.elems) throw new Error('an index is selected in a value that is not an array (§5.6.1.2)');
        const es = elemsOf(n, all);
        if (el >= es.length) {
          if (c.mandatory) throw new Error('a mandatory claim is not in the credential (§5.6.3)');
          continue;
        }
        next.push(es[el]);
      }
    }
    sel = next;
  }
  for (const n of sel) {
    const sd = n.disclosed || n.hidden;
    if (c.sd === 'always' && !sd) {
      throw new Error('a selected claim is not selectively disclosable, and sd is always');
    }
    if (c.sd === 'never' && sd) {
      throw new Error('a selected claim is selectively disclosable, and sd is never');
    }
  }
}

export type RedirectPolicy = { mode: 'origin' } | { mode: 'any' } | { mode: 'to'; origins: string[] };

export interface HTTPResolverConfig {
  trustedPublisherOrigins?: string[];
  redirects?: RedirectPolicy;
  fetch?: typeof fetch;
  disableCache?: boolean;
}

export function newHTTPResolver(cfg: HTTPResolverConfig = {}): Resolver {
  const hints = {
    all: 'leave Config.TrustedPublisherOrigins empty',
    finer: 'list the origin and refuse the other vct in a Resolver that wraps this one',
  };
  for (const [i, e] of (cfg.trustedPublisherOrigins ?? []).entries()) {
    const why = checkOriginEntry(e, hints);
    if (why) throw new Error(`typemeta: Config.TrustedPublisherOrigins[${i}] ${why}`);
  }
  const trusted = newOriginList(cfg.trustedPublisherOrigins ?? []);
  let redirects: Redirects | undefined;
  const p = cfg.redirects ?? { mode: 'origin' };
  if (p.mode === 'any') redirects = redirectsAny();
  else if (p.mode === 'to') {
    if (!p.origins.length) throw new Error('typemeta: Config.Redirects is RedirectTo with no origin');
    redirects = redirectsTo(p.origins);
  }
  const maxCacheBytes = 4 << 20;
  let cacheBytes = 0;
  const cache = new Map<string, { doc: Buffer; expires: number }>();
  const rank = (e: { expires: number }, now: number) => (e.expires !== 0 && now >= e.expires ? 0 : e.expires === 0 ? 1 : 2);
  const cost = (key: string, d: Buffer) => d.length + 2 * key.length + 256;
  const remember = (ck: string, doc: Buffer, expires: number): void => {
    const size = cost(ck, doc);
    if (size > maxCacheBytes) return;
    const old = cache.get(ck);
    if (old) {
      cache.delete(ck);
      cacheBytes -= cost(ck, old.doc);
    }
    if (cacheBytes + size > maxCacheBytes) {
      const now = Date.now();
      const victims = [...cache].sort(([, a], [, b]) => rank(a, now) - rank(b, now));
      for (const [k, v] of victims) {
        if (cacheBytes + size <= maxCacheBytes) break;
        cache.delete(k);
        cacheBytes -= cost(k, v.doc);
      }
    }
    if (cacheBytes + size > maxCacheBytes) return;
    cache.set(ck, { doc, expires });
    cacheBytes += size;
  };
  return {
    async metadata(ref, signal) {
      if (!validURI(ref.vct)) {
        throw Object.assign(new Error('typemeta: vct is not a URI (RFC 3986)'), { cause: ErrNotFound });
      }
      let u: URL;
      try {
        u = parseURL(ref.vct);
      } catch {
        throw Object.assign(new Error('typemeta: vct is not an https URL'), { cause: ErrNotFound });
      }
      if (!httpsURL(u) || ref.vct.includes('#')) {
        throw Object.assign(new Error('typemeta: vct is not an https URL with a host, without userinfo or fragment'), {
          cause: ErrNotFound,
        });
      }
      if (!trusted.covers(u)) {
        throw Object.assign(new Error('typemeta: the origin of vct is not covered by Config.TrustedPublisherOrigins'), {
          cause: ErrNotFound,
        });
      }
      const ck = `${ref.vct}\n${ref.integrity ?? ''}`;
      const hit = cache.get(ck);
      if (hit && (hit.expires === 0 || Date.now() < hit.expires)) return Buffer.from(hit.doc);
      const limits: Limits = {
        timeoutMs: 5000,
        maxRedirects: 3,
        maxBytes: maxDocumentBytes,
        redirects,
        fetch: cfg.fetch,
      };
      let body: Buffer;
      let freshMs: number;
      try {
        const got = await cachedGet(ref.vct, ['application/json'], limits, 24 * 3600 * 1000, signal);
        body = got.body;
        freshMs = got.freshMs;
      } catch (err) {
        if (err instanceof StatusError && err.code === 404) {
          throw Object.assign(new Error('typemeta: the publisher answered 404'), { cause: ErrNotFound });
        }
        throw err;
      }
      if (!cfg.disableCache) {
        if (ref.integrity) {
          try {
            checkIntegrity(body, ref.integrity);
            remember(ck, body, 0);
          } catch {
            /* Load rejects */
          }
        } else if (freshMs > 0) {
          remember(ck, body, Date.now() + freshMs);
        }
      }
      return body;
    },
  };
}
