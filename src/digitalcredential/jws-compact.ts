import { p256 } from '@noble/curves/nist';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import type { SignerProvider } from '../common/signer/signer';
import { P256Provider } from '../common/signer/p256-provider';
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

export function base64urlStrict(s: string): Buffer {
  const b = Buffer.from(s, 'base64url');
  if (!/^[A-Za-z0-9_-]*$/.test(s) || b.toString('base64url') !== s) throw new Error('invalid base64url');
  return b;
}

export function decodeJSONSegment(segment: string, what = 'JWS segment'): Record<string, unknown> {
  let text: string;
  try {
    text = utf8.decode(base64urlStrict(segment));
  } catch {
    throw new Error(`${what} is not valid UTF-8`);
  }
  try {
    const v = JSON.parse(text);
    if (v && typeof v === 'object' && !Array.isArray(v)) return v as Record<string, unknown>;
  } catch {
    /* fall through */
  }
  throw new Error(`${what} is not a JSON object`);
}

export function encodeJWKFromP256Uncompressed(pub: Uint8Array): { kty: string; crv: string; x: string; y: string } {
  let uncompressed: Uint8Array;
  let crv: 'P-256' | 'secp256k1';
  if (pub.length === 65) {
    uncompressed = pub;
    try {
      p256.ProjectivePoint.fromHex(pub);
      crv = 'P-256';
    } catch {
      secp256k1.ProjectivePoint.fromHex(pub);
      crv = 'secp256k1';
    }
  } else {
    uncompressed = p256.ProjectivePoint.fromHex(pub).toRawBytes(false);
    crv = 'P-256';
  }
  return {
    kty: 'EC',
    crv,
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
