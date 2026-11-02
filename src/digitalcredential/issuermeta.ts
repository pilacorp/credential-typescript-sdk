import { checkOriginEntry, follows, newOriginList, redirectsAny, redirectsTo, type Redirects } from './internal/allowlist';
import { cachedGet } from './internal/httpcache';
import { ErrIssuerNotSupported, type PublicKey, type Resolver } from './issuerkey';
import { p256FromJWK } from './jws-compact';
import { httpsURL, parseURL } from './internal/url';
import { validURI } from './internal/uri';
import type { Limits } from './internal/safehttp';

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
  return `https://${authority}${wellKnown}${path.replace(/\/+$/, '')}`;
}

export class IssuerMetaResolver implements Resolver {
  private trusted;
  private redirects: Redirects | undefined;
  private cache = new Map<string, { keys: PublicKey[]; expires: number }>();
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
    const doc = JSON.parse(body.toString('utf8')) as Record<string, unknown>;
    if (typeof doc.issuer !== 'string') throw new Error('issuermeta: the issuer metadata has no string issuer');
    if (doc.issuer !== iss) {
      throw new Error("issuermeta: the issuer metadata names another issuer than the credential's iss");
    }
    const hasJWKS = Object.prototype.hasOwnProperty.call(doc, 'jwks');
    const hasURI = Object.prototype.hasOwnProperty.call(doc, 'jwks_uri');
    let set: Record<string, unknown>;
    if (hasJWKS === hasURI) {
      throw new Error('issuermeta: the issuer metadata must have exactly one of jwks and jwks_uri');
    }
    if (hasJWKS) {
      if (typeof doc.jwks !== 'object' || doc.jwks === null) throw new Error('issuermeta: jwks is not a JSON object');
      set = doc.jwks as Record<string, unknown>;
    } else {
      if (typeof doc.jwks_uri !== 'string' || !validURI(doc.jwks_uri)) {
        throw new Error('issuermeta: jwks_uri is not a URI');
      }
      const ju = parseURL(doc.jwks_uri);
      if (!httpsURL(ju)) throw new Error('issuermeta: jwks_uri is not an https URL with a host');
      const got = await cachedGet(
        doc.jwks_uri,
        ['application/jwk-set+json', 'application/json'],
        limits,
        maxCacheLifetimeMs,
        signal,
      );
      set = JSON.parse(got.body.toString('utf8')) as Record<string, unknown>;
    }
    const keys = signingKeys(set);
    if (!this.cfg.disableCache && freshMs > 0) {
      const size = 222 + iss.length + keys.length * 250;
      if (this.used + size <= maxCacheBytes) {
        this.cache.set(iss, { keys, expires: Date.now() + freshMs });
        this.used += size;
      }
    }
    return keys;
  }
}

function signingKeys(set: Record<string, unknown>): PublicKey[] {
  const elems = set.keys;
  if (!Array.isArray(elems)) throw new Error('issuermeta: the JWK Set has no keys array');
  const keys: PublicKey[] = [];
  for (const e of elems) {
    if (typeof e !== 'object' || e === null) throw new Error('issuermeta: the JWK Set holds an element that is not a JWK object');
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
