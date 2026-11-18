import { createHash } from 'node:crypto';
import { checkOriginEntry, newOriginList, redirectsAny, redirectsTo, type Redirects } from './internal/allowlist';
import { cachedGet } from './internal/httpcache';
import { checkIntegrityBytes, wellFormedIntegrity } from './internal/sri';
import { httpsURL, parseURL } from './internal/url';
import { validURI } from './internal/uri';
import type { Limits } from './internal/safehttp';
import { StatusError } from './internal/safehttp';
import { hasOwn, parseJSONBytes, setOwn } from '../common/util/json';
import type { IssuedNode } from '../common/sdjwt';

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
    opts: { allDisclosures?: boolean; issued?: IssuedNode } = {},
  ): void {
    const issued = opts.issued ?? inTheClear(claims);
    const budget = { left: maxClaimVisits };
    for (const [i, c] of this.claims.entries()) {
      try {
        checkClaim(c, issued, Boolean(opts.allDisclosures), budget);
      } catch (err) {
        if (err === errBudget) {
          throw Object.assign(
            new Error(
              `typemeta: checking the payload against the claim metadata needs over ${maxClaimVisits} units (one per value read, one more per 64 bytes of a key), the SDK's limit`,
            ),
            { cause: ErrClaims },
          );
        }
        throw Object.assign(
          new Error(`typemeta: claims[${i}] with path ${JSON.stringify(c.path)}: ${(err as Error).message}`),
          { cause: ErrViolated },
        );
      }
    }
  }

  /**
   * Checks payload, the claims an issuer is about to sign with nothing
   * concealed yet, as validateClaims with allDisclosures checks the
   * credential it becomes: each path in disclose is made a disclosure and the
   * rest stays in the clear (SD-JWT VC draft 19 §5.6).
   */
  validateIssuance(payload: Record<string, unknown>, disclose: PathEl[][]): void {
    const root = inTheClear(payload);
    disclose.forEach((path, i) => {
      if (!path.length) throw new Error(`typemeta: disclose[${i}] is an empty path`);
      let n: IssuedNode | undefined = root;
      for (const el of path) {
        if (typeof el === 'string') n = n.fields && hasOwn(n.fields, el) ? n.fields[el] : undefined;
        else if (typeof el === 'number') n = n.elems?.[el];
        else throw new Error(`typemeta: disclose[${i}] ${JSON.stringify(path)} has an element that is not a string or an index`);
        if (!n) throw new Error(`typemeta: disclose[${i}] ${JSON.stringify(path)} names no claim of the payload`);
      }
      n.disclosed = true;
    });
    this.validateClaims(payload, { allDisclosures: true, issued: root });
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
    const obj = parseJSONBytes(b) as { vct?: unknown };
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
  let obj: Record<string, unknown>;
  try {
    obj = parseJSONBytes(raw) as Record<string, unknown>;
  } catch (err) {
    throw Object.assign(new Error(`typemeta: ${(err as Error).message}`), { cause: ErrInvalid });
  }
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

/** The shape of claims nothing was concealed in: no value is disclosed or hidden. */
function inTheClear(v: unknown): IssuedNode {
  const n: IssuedNode = { disclosed: false, hidden: false, hiddenFields: 0 };
  if (Array.isArray(v)) n.elems = v.map(inTheClear);
  else if (v && typeof v === 'object') {
    n.fields = {};
    for (const [k, child] of Object.entries(v)) setOwn(n.fields, k, inTheClear(child));
  }
  return n;
}

function elemsOf(n: IssuedNode, all: boolean): IssuedNode[] {
  const list = n.elems ?? [];
  return all ? list.filter((e) => !e.hidden) : list;
}

// Bounds the work of one validateClaims call, one unit per value read and one
// more per 64 bytes of a key looked up: claims times the values a path selects
// has no bound the other limits give.
const maxClaimVisits = 1 << 20;
const errBudget = new Error('over the budget');

function checkClaim(c: Claim, root: IssuedNode, all: boolean, budget: { left: number }): void {
  let sel: IssuedNode[] = [root];
  for (const el of c.path) {
    const next: IssuedNode[] = [];
    for (const n of sel) {
      if (n.hidden) continue;
      // Charged before the read: null and, with all, an index read the whole array.
      let cost = 1;
      if (typeof el === 'string') cost += Math.floor(Buffer.byteLength(el) / 64);
      else if (el === null || all) cost = n.elems?.length ?? 0;
      budget.left -= cost;
      if (budget.left < 0) throw errBudget;
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
        for (const e of elemsOf(n, all)) next.push(e);
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
