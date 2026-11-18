import { p256 } from '@noble/curves/nist';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import type { SignerProvider } from '../common/signer/signer';
import { P256Provider } from '../common/signer/p256-provider';
import { decodeBase64URLStrict } from '../common/util/base64url';
import { hasOwn } from '../common/util/json';

const utf8 = new TextDecoder('utf-8', { fatal: true });
const curves: Record<string, typeof p256 | typeof secp256k1> = { ES256: p256, ES256K: secp256k1 };

export const ErrUnsupportedHeader = Object.assign(new Error('unsupported JWS header'), { name: 'UnsupportedHeader' });

export function isUnsupportedHeader(err: unknown): boolean {
  return Boolean(
    err &&
      typeof err === 'object' &&
      ((err as Error).name === 'UnsupportedHeader' || (err as { cause?: unknown }).cause === ErrUnsupportedHeader),
  );
}

function equalFoldASCII(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    let x = a.charCodeAt(i);
    let y = b.charCodeAt(i);
    if (x >= 65 && x <= 90) x += 32;
    if (y >= 65 && y <= 90) y += 32;
    if (x !== y) return false;
  }
  return true;
}

function fullMediaType(v: string): string | undefined {
  if (!v || v.includes(';')) return undefined;
  return v.includes('/') ? v : `application/${v}`;
}

export function typIs(typ: unknown, want: string): boolean {
  if (typeof typ !== 'string') return false;
  const t = fullMediaType(typ);
  const w = fullMediaType(want);
  return Boolean(t && w && equalFoldASCII(t, w));
}

function checkHeaderExtensions(h: Record<string, unknown>): void {
  if (hasOwn(h, 'crit') || hasOwn(h, 'b64')) {
    throw Object.assign(new Error('the JWS header uses crit or b64, which this SDK does not implement'), {
      name: 'UnsupportedHeader',
      cause: ErrUnsupportedHeader,
    });
  }
}

export const base64urlStrict = decodeBase64URLStrict;

/**
 * checkDepth false reads a segment before its signature is checked, when only
 * a claim such as iss is needed; the depth rule then waits for the signature.
 */
export function decodeJSONSegment(segment: string, what = 'JWS segment', checkDepth = true): Record<string, unknown> {
  let text: string;
  try {
    text = utf8.decode(base64urlStrict(segment));
  } catch {
    throw new Error(`${what} is not valid UTF-8`);
  }
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch {
    throw new Error(`${what} is not a JSON object`);
  }
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error(`${what} is not a JSON object`);
  if (checkDepth) checkJSONDepth(v, what);
  return v as Record<string, unknown>;
}

// The deepest nesting of objects and arrays a header or payload may have
// (RFC 8259 §9 lets a parser limit it), the Go SDK's jose.MaxJSONDepth.
const maxJSONDepth = 64;

/** A header, a payload or claims for one nest deeper than both SDKs read. */
export class JSONDepthError extends Error {}

/** Throws JSONDepthError when v, counted as the first level, nests deeper than 64. */
export function checkJSONDepth(v: unknown, what: string): void {
  if (nestsDeeper(v, maxJSONDepth)) throw new JSONDepthError(`${what}: nesting deeper than ${maxJSONDepth}`);
}

/**
 * What the caller gave, as the JSON it serializes to: every check after this
 * reads what is signed, not an object whose toJSON says something else.
 * Refuses nesting deeper than 64 first, which also bounds the serializer.
 */
export function jsonForm(v: object, what: string): Record<string, unknown> {
  checkJSONDepth(v, what);
  let copy: unknown;
  try {
    copy = JSON.parse(JSON.stringify(v));
  } catch (err) {
    throw Object.assign(new Error(`${what} does not serialize to JSON`), { cause: err });
  }
  if (!copy || typeof copy !== 'object' || Array.isArray(copy)) throw new Error(`${what} is not a JSON object`);
  // The serializer asks toJSON again, with the key; the copy is what it answered then.
  checkJSONDepth(copy, what);
  return copy as Record<string, unknown>;
}

// Counts the JSON form: a value with toJSON (a Date, a Buffer) is what it serializes to.
function nestsDeeper(v: unknown, levels: number): boolean {
  if (v && typeof (v as { toJSON?: unknown }).toJSON === 'function') v = (v as { toJSON(): unknown }).toJSON();
  if (!v || typeof v !== 'object') return false;
  if (levels === 0) return true;
  for (const child of Array.isArray(v) ? v : Object.values(v)) {
    if (nestsDeeper(child, levels - 1)) return true;
  }
  return false;
}

export function encodeJWKFromP256Uncompressed(
  pub: Uint8Array,
  alg: 'ES256' | 'ES256K' = 'ES256',
): { kty: string; crv: string; x: string; y: string } {
  const curve = alg === 'ES256K' ? secp256k1 : p256;
  const uncompressed = curve.ProjectivePoint.fromHex(pub).toRawBytes(false);
  return {
    kty: 'EC',
    crv: alg === 'ES256K' ? 'secp256k1' : 'P-256',
    x: Buffer.from(uncompressed.subarray(1, 33)).toString('base64url'),
    y: Buffer.from(uncompressed.subarray(33)).toString('base64url'),
  };
}

export function algForECJWK(jwk: { crv?: string }): 'ES256' | 'ES256K' {
  if (jwk.crv === 'secp256k1') return 'ES256K';
  if (jwk.crv === 'P-256') return 'ES256';
  throw new Error('cnf.jwk must be a P-256 or secp256k1 EC key');
}

/** Uncompressed EC public key from a cnf.jwk (P-256 or secp256k1). */
export function p256FromJWK(jwk: { x?: string; y?: string; crv?: string; kty?: string; d?: string }): Uint8Array {
  if (hasOwn(jwk, 'd')) throw new Error('cnf.jwk carries a private key (d)');
  if (jwk.kty !== 'EC' || !jwk.x || !jwk.y) {
    throw new Error('cnf.jwk must be a P-256 or secp256k1 EC key');
  }
  const curve = jwk.crv === 'secp256k1' ? secp256k1 : jwk.crv === 'P-256' ? p256 : undefined;
  if (!curve) throw new Error('cnf.jwk must be a P-256 or secp256k1 EC key');
  const x = base64urlStrict(jwk.x);
  const y = base64urlStrict(jwk.y);
  if (x.length !== 32 || y.length !== 32) throw new Error('cnf.jwk x and y must be 32 bytes');
  const uncompressed = new Uint8Array(65);
  uncompressed[0] = 0x04;
  uncompressed.set(x, 1);
  uncompressed.set(y, 33);
  return curve.ProjectivePoint.fromHex(uncompressed).toRawBytes(false);
}

export async function signCompactJWS(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  signer: SignerProvider,
): Promise<string> {
  const h = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
  const p = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const input = `${h}.${p}`;
  const digest = sha256(Buffer.from(input, 'utf8'));
  let sig = await signer.sign(digest);
  if (sig.length === 65) sig = sig.subarray(0, 64);
  return `${input}.${Buffer.from(sig).toString('base64url')}`;
}

export function verifyCompactJWS(
  token: string,
  pubUncompressed: Uint8Array,
  allowedAlgs = ['ES256', 'ES256K'],
): Record<string, unknown> {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('invalid JWS');
  const header = decodeJSONSegment(parts[0], 'JWS header') as { alg?: string; crit?: unknown; b64?: unknown };
  checkHeaderExtensions(header);
  const curve = header.alg ? curves[header.alg] : undefined;
  if (!curve || !allowedAlgs.includes(header.alg!)) {
    throw new Error(`alg not allowed: ${header.alg}`);
  }
  const digest = sha256(Buffer.from(`${parts[0]}.${parts[1]}`, 'utf8'));
  const sig = base64urlStrict(parts[2]);
  if (sig.length !== 64) throw new Error('signature is not 64 bytes (R || S)');
  const ok = curve.verify(sig, digest, pubUncompressed, { lowS: false });
  if (!ok) throw new Error('signature verification failed');
  return decodeJSONSegment(parts[1], 'JWS payload');
}

export function peekHeader(token: string): Record<string, unknown> {
  const [h] = token.split('.');
  const header = decodeJSONSegment(h, 'JWS header');
  checkHeaderExtensions(header);
  return header;
}

export { P256Provider };

// The seconds a NumericDate may hold (RFC 7519 §2), within the dates the Go
// SDK computes: -292277022400-03-01 to 292277024627-12-06.
const minUnix = -9223372028741760000;
const maxUnix = 9223371974719179007;

/** A Date whose seconds are a NumericDate; an Invalid Date would be signed as null. */
export function isValidDate(d: unknown): d is Date {
  return d instanceof Date && isNumericDate(Math.floor(d.getTime() / 1000));
}

/** Whether v is a NumericDate both SDKs read: a number, a fraction allowed, within that range. */
export function isNumericDate(v: unknown): v is number {
  return typeof v === 'number' && v >= minUnix && v < maxUnix;
}
