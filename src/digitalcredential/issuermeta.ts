import { checkOriginEntry, follows, newOriginList, redirectsAny, redirectsTo, type Redirects } from './internal/allowlist';
import { cachedGet } from './internal/httpcache';
import { ErrIssuerNotSupported, ErrNoUsableKey, type PublicKey, type Resolver } from './issuerkey';
import { p256FromJWK } from './jws-compact';
import { httpsURL, parseURL } from './internal/url';
import { validURI } from './internal/uri';
import type { Limits } from './internal/safehttp';
import { parseJSONBytes } from '../common/util/json';

export {
  ErrAddressBlocked,
  ErrBodyTooLarge,
  ErrContentTypeNotAccepted,
  ErrNotFollowed as ErrRedirectNotAllowed,
  ErrRedirectTargetNotAllowed,
  ErrTooManyRedirects,
  StatusError,
} from './internal/safehttp';

const wellKnown = '/.well-known/jwt-vc-issuer';

// contentFault is a fault in what the issuer published. It wraps ErrNoUsableKey,
// so the verifier reports ISSUER_KEY_NOT_FOUND rather than a retryable failure
// to reach the issuer: fetching again returns the same bad document.
function contentFault(message: string): Error {
  return Object.assign(new Error(`issuermeta: ${message}`), { cause: ErrNoUsableKey });
}

function parseObject(bytes: Uint8Array, what: string): Record<string, unknown> {
  let v: unknown;
  try {
    v = parseJSONBytes(bytes);
  } catch (err) {
    throw contentFault(`${what} is not a JSON object: ${(err as Error).message}; the issuer must fix it`);
  }
  if (typeof v !== 'object' || v === null || Array.isArray(v)) {
    throw contentFault(`${what} is not a JSON object; the issuer must fix it`);
  }
  return v as Record<string, unknown>;
}
const maxCacheBytes = 4 << 20;
const maxCacheLifetimeMs = 24 * 3600 * 1000;

export type RedirectPolicy = { mode: 'origin' } | { mode: 'any' } | { mode: 'to'; origins: string[] };

export function redirectTo(...origins: string[]): RedirectPolicy {
  return { mode: 'to', origins: [...origins] };
}
export function redirectAny(): RedirectPolicy {
  return { mode: 'any' };
}

export interface ResolverConfig {
  trustedIssuerOrigins?: string[];
  redirects?: RedirectPolicy;
  fetch?: typeof fetch;
  disableCache?: boolean;
}

export function metadataURL(iss: string): string {
  if (!validURI(iss)) throw Object.assign(new Error('issuermeta: iss is not a URI (RFC 3986)'), { cause: ErrIssuerNotSupported });
  let u: URL;
  try {
    u = parseURL(iss);
  } catch {
    throw Object.assign(new Error('issuermeta: iss is not an https URL with a host'), { cause: ErrIssuerNotSupported });
  }
  if (!httpsURL(u) || /[?#]/.test(iss)) {
    throw Object.assign(new Error('issuermeta: iss is not an https URL with a host and no query or fragment'), {
      cause: ErrIssuerNotSupported,
    });
  }
  const rest = iss.slice(iss.indexOf('://') + 3);
  const slash = rest.indexOf('/');
  const authority = slash < 0 ? rest : rest.slice(0, slash);
  const path = slash < 0 ? '' : rest.slice(slash);
  // Decode to octets, not UTF-8: RFC 3986 §2.1 lets %ff name any byte, and
  // validURI has already refused a "%" not followed by two hex digits.
  const decoded = path.replace(/%([0-9A-Fa-f]{2})/g, (_, hex: string) => String.fromCharCode(parseInt(hex, 16)));
  if (hasDotSegment(decoded)) {
    throw Object.assign(new Error('issuermeta: iss path has a "." or ".." segment'), { cause: ErrIssuerNotSupported });
  }
  return `https://${authority}${wellKnown}${path.replace(/\/+$/, '')}`;
}

function hasDotSegment(path: string): boolean {
  return path.split(/[/\\]/).some((s) => {
    const seg = s.split(';')[0];
    return seg === '.' || seg === '..';
  });
}

export class IssuerMetaResolver implements Resolver {
  private trusted;
  private redirects: Redirects | undefined;
  private cache = new Map<string, { keys: PublicKey[]; expires: number; size: number }>();
  private used = 0;

  constructor(private readonly cfg: ResolverConfig) {
    const hints = {
      all: 'leave Config.TrustedIssuerOrigins empty',
      finer: 'list the origin and refuse the other iss in a Resolver that wraps this one',
    };
    for (const [i, e] of (cfg.trustedIssuerOrigins ?? []).entries()) {
      const why = checkOriginEntry(e, hints);
      if (why) throw new Error(`issuermeta: Config.TrustedIssuerOrigins[${i}] ${why}`);
    }
    this.trusted = newOriginList(cfg.trustedIssuerOrigins ?? []);
    const p = cfg.redirects ?? { mode: 'origin' };
    if (p.mode === 'any') this.redirects = redirectsAny();
    else if (p.mode === 'to') {
      if (!p.origins.length) throw new Error('issuermeta: Config.Redirects is RedirectTo with no origin');
      for (const [i, e] of p.origins.entries()) {
        const why = checkOriginEntry(e, { all: 'use RedirectAny()' });
        if (why) throw new Error(`issuermeta: Config.Redirects RedirectTo[${i}] ${why}`);
      }
      this.redirects = redirectsTo(p.origins);
    }
  }

  async keys(iss: string, signal?: AbortSignal): Promise<PublicKey[]> {
    if (!iss) {
      throw Object.assign(
        new Error('issuermeta: the credential has no iss; issuermeta resolves only https issuers'),
        { cause: ErrIssuerNotSupported },
      );
    }
    const meta = metadataURL(iss);
    const u = parseURL(iss);
    if (!this.trusted.covers(u)) {
      throw Object.assign(
        new Error('issuermeta: the origin of iss is not covered by Config.TrustedIssuerOrigins'),
        { cause: ErrIssuerNotSupported },
      );
    }
    const hit = this.cache.get(iss);
    if (hit && Date.now() < hit.expires) return hit.keys.slice();
    const limits: Limits = {
      timeoutMs: 5000,
      maxRedirects: 3,
      maxBytes: 64 << 10,
      redirects: this.redirects,
      fetch: this.cfg.fetch,
    };
    const { body, freshMs } = await cachedGet(meta, ['application/json'], limits, maxCacheLifetimeMs, signal);
    const doc = parseObject(body, 'the issuer metadata');
    if (typeof doc.issuer !== 'string') throw contentFault('the issuer metadata has no string issuer');
    if (doc.issuer !== iss) {
      throw contentFault("the issuer metadata names another issuer than the credential's iss; it cannot be used");
    }
    const hasJWKS = Object.prototype.hasOwnProperty.call(doc, 'jwks');
    const hasURI = Object.prototype.hasOwnProperty.call(doc, 'jwks_uri');
    let set: Record<string, unknown>;
    if (hasJWKS === hasURI) {
      throw contentFault(`the issuer metadata has ${hasJWKS ? 'both' : 'neither'} jwks ${hasJWKS ? 'and' : 'nor'} jwks_uri; it must have exactly one`);
    }
    if (hasJWKS) {
      if (typeof doc.jwks !== 'object' || doc.jwks === null || Array.isArray(doc.jwks)) {
        throw contentFault('jwks is not a JSON object');
      }
      set = doc.jwks as Record<string, unknown>;
    } else {
      if (typeof doc.jwks_uri !== 'string' || !validURI(doc.jwks_uri)) {
        throw contentFault('jwks_uri is not a URI');
      }
      // An RFC 3986 URI can still be one the URL parser refuses, such as a host with "%20".
      let ju: URL | undefined;
      try {
        ju = parseURL(doc.jwks_uri);
      } catch {
        ju = undefined;
      }
      if (!ju || !httpsURL(ju)) throw contentFault('jwks_uri is not an https URL with a host');
      const got = await cachedGet(
        doc.jwks_uri,
        ['application/jwk-set+json', 'application/json'],
        limits,
        maxCacheLifetimeMs,
        signal,
      );
      set = parseObject(got.body, 'the JWK Set from jwks_uri');
    }
    const keys = signingKeys(set);
    if (!this.cfg.disableCache && freshMs > 0) {
      const size = 222 + iss.length + keys.length * 250;
      const old = this.cache.get(iss);
      if (old) {
        this.used -= old.size;
        this.cache.delete(iss);
      }
      if (this.used + size > maxCacheBytes) {
        const now = Date.now();
        for (const [k, e] of this.cache) {
          if (e.expires <= now) {
            this.used -= e.size;
            this.cache.delete(k);
          }
        }
      }
      if (this.used + size <= maxCacheBytes) {
        this.cache.set(iss, { keys, expires: Date.now() + freshMs, size });
        this.used += size;
      }
    }
    return keys;
  }
}

function signingKeys(set: Record<string, unknown>): PublicKey[] {
  const elems = set.keys;
  if (!Array.isArray(elems)) throw contentFault('the JWK Set has no keys array');
  const keys: PublicKey[] = [];
  for (const e of elems) {
    if (typeof e !== 'object' || e === null || Array.isArray(e)) {
      throw contentFault('the JWK Set holds an element that is not a JWK object');
    }
    const m = e as Record<string, unknown>;
    if (m.kid !== undefined && typeof m.kid !== 'string') continue;
    if (m.use !== undefined && m.use !== 'sig') continue;
    if (m.alg !== undefined && m.alg !== 'ES256' && m.alg !== 'ES256K') continue;
    if (m.key_ops !== undefined) {
      if (!Array.isArray(m.key_ops) || !m.key_ops.includes('verify')) continue;
    }
    try {
      const publicKey = p256FromJWK(m as { x?: string; y?: string; crv?: string; kty?: string });
      keys.push({ kid: typeof m.kid === 'string' ? m.kid : undefined, publicKey });
    } catch {
      continue;
    }
  }
  return keys;
}

export function newResolver(cfg: ResolverConfig = {}): IssuerMetaResolver {
  return new IssuerMetaResolver(cfg);
}
