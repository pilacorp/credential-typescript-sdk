import { p256 } from '@noble/curves/nist';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import type { SignerProvider } from '../common/signer/signer';
import { P256Provider } from '../common/signer/p256-provider';

const utf8 = new TextDecoder('utf-8', { fatal: true });
const curves: Record<string, typeof p256 | typeof secp256k1> = { ES256: p256, ES256K: secp256k1 };

export function typIs(typ: unknown, want: string): boolean {
  if (typeof typ !== 'string') return false;
  const t = typ.toLowerCase();
  return t === want || t === `application/${want}`;
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
  const uncompressed = pub.length === 65 ? pub : p256.ProjectivePoint.fromHex(pub).toRawBytes(false);
  return {
    kty: 'EC',
    crv: 'P-256',
    x: Buffer.from(uncompressed.subarray(1, 33)).toString('base64url'),
    y: Buffer.from(uncompressed.subarray(33)).toString('base64url'),
  };
}

export function p256FromJWK(jwk: { x?: string; y?: string; crv?: string; kty?: string; d?: string }): Uint8Array {
  if ('d' in jwk) throw new Error('cnf.jwk carries a private key (d)');
  if (jwk.kty !== 'EC' || !jwk.x || !jwk.y) {
    throw new Error('cnf.jwk must be a P-256 EC key');
  }
  const curve = jwk.crv === 'secp256k1' ? secp256k1 : jwk.crv === 'P-256' ? p256 : undefined;
  if (!curve) throw new Error('cnf.jwk must be a P-256 EC key');
  const x = Buffer.from(jwk.x, 'base64url');
  const y = Buffer.from(jwk.y, 'base64url');
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
  return decodeJSONSegment(h, 'JWS header');
}

export { P256Provider };
