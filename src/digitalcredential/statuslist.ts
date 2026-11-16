import { deflateSync, inflateSync } from 'node:zlib';
import type { SigningKey } from './issuerkey';
import { selectKey, type Resolver } from './issuerkey';
import { base64urlStrict, peekHeader, signCompactJWS, typIs, verifyCompactJWS } from './jws-compact';
import { nonNegativeInt } from './internal/jsonint';
import { checkURI } from './internal/uri';
import { allows, get, StatusError } from './internal/safehttp';
import { parseURL } from './internal/url';

export const ErrIndexOutOfBounds = Object.assign(new Error('statuslist: index out of bounds'), { name: 'StatusListError' });
export const ErrURINotSupported = Object.assign(new Error('statuslist: status list uri not supported'), {
  name: 'StatusListError',
});
export const ErrTokenType = Object.assign(new Error('statuslist: token typ is not statuslist+jwt'), {
  name: 'StatusListError',
});
export const ErrSubjectMismatch = Object.assign(
  new Error('statuslist: token sub is not the uri of the Referenced Token'),
  { name: 'StatusListError' },
);
export const ErrIssuerMismatch = Object.assign(
  new Error('statuslist: token iss is not the issuer of the Referenced Token'),
  { name: 'StatusListError' },
);
export const ErrIssuedInFuture = Object.assign(new Error('statuslist: token iat is in the future'), {
  name: 'StatusListError',
});
export const ErrTooOld = Object.assign(new Error('statuslist: token is older than Config.MaxAge'), {
  name: 'StatusListError',
});

export { StatusError };

const maxListBytes = 16 << 20;
const maxCacheBytes = 32 << 20;
const typStatusList = 'statuslist+jwt';
const maxTokenBytes = 1 << 20;
const defaultClockSkewMs = 60_000;
const maxCacheLifetimeMs = 24 * 3600 * 1000;

function validBits(bits: number): boolean {
  return bits === 1 || bits === 2 || bits === 4 || bits === 8;
}

export class List {
  constructor(readonly bits: number, private b: Buffer) {}

  static new(size: number, bits: number): List {
    if (!validBits(bits)) throw new Error(`statuslist: bits ${bits}, want 1, 2, 4 or 8`);
    if (size < 0 || size > (maxListBytes * 8) / bits) {
      throw new Error(`statuslist: size ${size} out of range for ${bits}-bit entries`);
    }
    return new List(bits, Buffer.alloc(Math.floor((size * bits + 7) / 8)));
  }

  static fromBytes(b: Uint8Array, bits: number): List {
    if (!validBits(bits)) throw new Error(`statuslist: bits ${bits}, want 1, 2, 4 or 8`);
    if (b.length > maxListBytes) throw new Error(`statuslist: ${b.length} bytes, want at most ${maxListBytes}`);
    return new List(bits, Buffer.from(b));
  }

  entries(): number {
    return (this.b.length * 8) / this.bits;
  }

  bytes(): Buffer {
    return Buffer.from(this.b);
  }

  get(i: number): number {
    const { at, shift } = this.position(i);
    return (this.b[at] >> shift) & this.mask();
  }

  set(i: number, v: number): void {
    const { at, shift } = this.position(i);
    if (v > this.mask()) throw new Error(`statuslist: value ${v} does not fit in ${this.bits} bits`);
    this.b[at] = (this.b[at] & ~(this.mask() << shift)) | (v << shift);
  }

  encode(): string {
    const z = deflateSync(this.b, { level: 9 });
    return z.toString('base64url');
  }

  async issueToken(claims: TokenClaims, key: SigningKey): Promise<string> {
    if (!claims.sub) throw new Error('statuslist: Sub is required');
    checkURI(claims.sub);
    if (!claims.issuedAt) throw new Error('statuslist: IssuedAt is required');
    if ((claims.ttlSeconds ?? 0) < 0) throw new Error('statuslist: TTL is negative');
    const payload: Record<string, unknown> = { ...(claims.other ?? {}) };
    for (const name of ['sub', 'iat', 'exp', 'ttl', 'status_list']) {
      if (name in (claims.other ?? {})) throw new Error(`statuslist: Other holds ${name}`);
    }
    payload.sub = claims.sub;
    payload.iat = Math.floor(claims.issuedAt.getTime() / 1000);
    if (claims.expiry) payload.exp = Math.floor(claims.expiry.getTime() / 1000);
    if (claims.ttlSeconds) payload.ttl = claims.ttlSeconds;
    payload.status_list = { bits: this.bits, lst: this.encode() };
    const header: Record<string, unknown> = { alg: 'ES256', typ: typStatusList };
    if (key.kid) header.kid = key.kid;
    return signCompactJWS(header, payload, key.signer);
  }

  private mask(): number {
    return (1 << this.bits) - 1;
  }

  private position(i: number): { at: number; shift: number } {
    const n = this.entries();
    if (i < 0 || i >= n) throw new Error(`statuslist: index ${i} outside [0, ${n})`);
    const perByte = 8 / this.bits;
    return { at: Math.floor(i / perByte), shift: (i % perByte) * this.bits };
  }
}

export function decodeList(lst: string, bits: number): List {
  if (!validBits(bits)) throw new Error(`statuslist: bits ${bits}, want 1, 2, 4 or 8`);
  const raw = base64urlStrict(lst);
  if (raw.length >= 2 && (raw[1] & 0x20) !== 0) throw new Error('statuslist: lst uses a preset dictionary');
  let b: Buffer;
  try {
    b = inflateSync(raw, { maxOutputLength: maxListBytes });
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ERR_BUFFER_TOO_LARGE') {
      throw new Error(`statuslist: lst inflates past ${maxListBytes} bytes`);
    }
    throw err;
  }
  return new List(bits, Buffer.from(b));
}

export interface TokenClaims {
  sub: string;
  issuedAt: Date;
  expiry?: Date;
  ttlSeconds?: number;
  other?: Record<string, unknown>;
}

export interface Ref {
  uri: string;
  index: number;
}

export function validateRef(r: Ref): void {
  checkURI(r.uri);
  if (r.index < 0) throw new Error(`statuslist: Ref.Index ${r.index} is negative`);
}

export interface CheckerConfig {
  issuers: Resolver;
  fetch?: typeof fetch;
  insecureHTTP?: boolean;
  clockSkewMs?: number;
  maxAgeMs?: number;
  allowedAlgs?: string[];
}

interface cacheEntry {
  list: List;
  iat: number;
  expires: number;
  size: number;
}

export class Checker {
  private cache = new Map<string, cacheEntry>();
  private cacheBytes = 0;
  private skew: number;
  private maxAge: number;
  private algs: string[];

  constructor(private readonly cfg: CheckerConfig) {
    if (!cfg.issuers) throw new Error('statuslist: Config.Issuers is required');
    if ((cfg.clockSkewMs ?? 0) < 0) throw new Error('statuslist: ClockSkew is negative');
    if ((cfg.maxAgeMs ?? 0) < 0) throw new Error('statuslist: MaxAge is negative');
    this.skew = cfg.clockSkewMs ?? defaultClockSkewMs;
    this.maxAge = cfg.maxAgeMs ?? 0;
    this.algs = cfg.allowedAlgs?.length ? cfg.allowedAlgs : ['ES256', 'ES256K'];
  }

  private remember(key: string, e: Omit<cacheEntry, 'size'>): void {
    const size = Math.ceil((e.list.entries() * e.list.bits) / 8) + 2 * key.length + 256;
    const old = this.cache.get(key);
    if (old && old.iat > e.iat && Date.now() < old.expires) return;
    if (old) {
      this.cache.delete(key);
      this.cacheBytes -= old.size;
    }
    const now = Date.now();
    for (const [k, v] of this.cache) {
      if (now >= v.expires) {
        this.cache.delete(k);
        this.cacheBytes -= v.size;
      }
    }
    if (this.cacheBytes + size > maxCacheBytes) return;
    this.cache.set(key, { ...e, size });
    this.cacheBytes += size;
  }

  async status(ref: Ref, iss: string, signal?: AbortSignal): Promise<number> {
    validateRef(ref);
    const u = parseURL(ref.uri);
    if (!allows({ timeoutMs: 5000, maxRedirects: 3, maxBytes: maxTokenBytes, allowHTTP: this.cfg.insecureHTTP }, u)) {
      throw ErrURINotSupported;
    }
    const key = `${iss}\n${ref.uri}`;
    let l = this.cached(key);
    if (!l || ref.index >= l.entries()) {
      l = await this.load(key, ref, iss, signal);
    }
    if (ref.index >= l.entries()) {
      throw Object.assign(
        new Error(
          `index ${ref.index} is outside the list of ${l.entries()} entries (draft-ietf-oauth-status-list-21 §8.3 step 6)`,
        ),
        { cause: ErrIndexOutOfBounds },
      );
    }
    return l.get(ref.index);
  }

  private cached(key: string): List | undefined {
    const e = this.cache.get(key);
    if (!e || Date.now() >= e.expires) return undefined;
    return e.list;
  }

  private async load(key: string, ref: Ref, iss: string, signal?: AbortSignal): Promise<List> {
    const fetched = Date.now();
    const { body } = await get(
      ref.uri,
      [`application/${typStatusList}`],
      {
        timeoutMs: 5000,
        maxRedirects: 3,
        maxBytes: maxTokenBytes,
        allowHTTP: this.cfg.insecureHTTP,
        anyContentType: true,
        fetch: this.cfg.fetch,
      },
      signal,
    );
    const token = body.toString('utf8');
    const header = peekHeader(token);
    if (!typIs(header.typ, typStatusList)) throw ErrTokenType;
    const keys = await this.cfg.issuers.keys(iss);
    const pub = selectKey(keys, typeof header.kid === 'string' ? header.kid : undefined);
    const claims = verifyCompactJWS(token, pub.publicKey, this.algs) as Record<string, unknown>;
    if (claims.sub !== ref.uri) throw ErrSubjectMismatch;
    if (claims.iss !== undefined && claims.iss !== iss) throw ErrIssuerMismatch;
    const iat = numericDate(claims.iat);
    if (iat === undefined) throw new Error('statuslist: token has no iat');
    const now = Date.now() / 1000;
    const skew = this.skew / 1000;
    if (iat > now + skew) throw ErrIssuedInFuture;
    const exp = numericDate(claims.exp);
    if (exp !== undefined && now >= exp + skew) throw new Error('statuslist: token expired');
    const nbf = numericDate(claims.nbf);
    if (nbf !== undefined && now < nbf - skew) throw new Error('statuslist: token not yet valid');
    if (claims.aud !== undefined) throw new Error('statuslist: token has aud');
    if (this.maxAge > 0 && iat < now - this.maxAge / 1000 - skew) throw ErrTooOld;
    let ttl = 0;
    if (claims.ttl !== undefined) {
      if (typeof claims.ttl !== 'number' || !(claims.ttl > 0)) throw new Error('statuslist: token ttl is not a positive number');
      ttl = Math.min(maxCacheLifetimeMs, claims.ttl * 1000);
    }
    const sl = claims.status_list as Record<string, unknown> | undefined;
    if (!sl || typeof sl !== 'object') throw new Error('statuslist: token status_list is not an object');
    if (typeof sl.bits !== 'number') throw new Error('statuslist: token status_list bits is not 1, 2, 4 or 8');
    let bits: number;
    try {
      bits = nonNegativeInt(String(sl.bits));
    } catch {
      throw new Error('statuslist: token status_list bits is not 1, 2, 4 or 8');
    }
    if (typeof sl.lst !== 'string') throw new Error('statuslist: token status_list lst is not a string');
    const list = decodeList(sl.lst, bits);
    if (ttl > 0) {
      let expires = fetched + ttl;
      if (exp !== undefined) expires = Math.min(expires, exp * 1000);
      if (this.maxAge > 0) expires = Math.min(expires, iat * 1000 + this.maxAge + this.skew);
      this.remember(key, { list, iat, expires });
    }
    return list;
  }
}

function numericDate(v: unknown): number | undefined {
  if (v === undefined) return undefined;
  if (typeof v !== 'number' || !Number.isFinite(v)) throw new Error('statuslist: date claim is not a number');
  return v;
}

export function refFromStatus(status: unknown): Ref | undefined {
  if (status === undefined) return undefined;
  if (typeof status !== 'object' || status === null || Array.isArray(status) || Object.keys(status as object).length === 0) {
    throw new Error('status is not a JSON object holding a status mechanism');
  }
  const sl = (status as { status_list?: unknown }).status_list;
  if (sl === undefined) return undefined;
  if (typeof sl !== 'object' || sl === null) throw new Error('status.status_list is not an object');
  const rec = sl as { uri?: unknown; idx?: unknown };
  if (typeof rec.uri !== 'string') throw new Error('status.status_list is not a JSON object with a string uri');
  if (typeof rec.idx !== 'number' || !Number.isInteger(rec.idx) || rec.idx < 0) {
    throw new Error('status_list idx is not a non-negative integer');
  }
  const idx = rec.idx;
  const r = { uri: rec.uri, index: idx };
  validateRef(r);
  return r;
}
