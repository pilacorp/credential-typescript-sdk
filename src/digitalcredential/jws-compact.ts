import { p256 } from '@noble/curves/nist';
import { sha256 } from '@noble/hashes/sha256';
import type { SignerProvider } from '../common/signer/signer';
import { P256Provider } from '../common/signer/p256-provider';

export function encodeJWKFromP256Uncompressed(pub: Uint8Array): { kty: string; crv: string; x: string; y: string } {
  const uncompressed = pub.length === 65 ? pub : p256.ProjectivePoint.fromHex(pub).toRawBytes(false);
  return {
    kty: 'EC',
    crv: 'P-256',
    x: Buffer.from(uncompressed.subarray(1, 33)).toString('base64url'),
    y: Buffer.from(uncompressed.subarray(33)).toString('base64url'),
  };
}

export function p256FromJWK(jwk: { x?: string; y?: string; crv?: string; kty?: string }): Uint8Array {
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) {
    throw new Error('cnf.jwk must be a P-256 EC key');
  }
  const x = Buffer.from(jwk.x, 'base64url');
  const y = Buffer.from(jwk.y, 'base64url');
  const uncompressed = new Uint8Array(65);
  uncompressed[0] = 0x04;
  uncompressed.set(x, 1);
  uncompressed.set(y, 33);
  return p256.ProjectivePoint.fromHex(uncompressed).toRawBytes(false);
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

export function verifyCompactJWS(token: string, pubUncompressed: Uint8Array, allowedAlgs = ['ES256']): Record<string, unknown> {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('invalid JWS');
  const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')) as { alg?: string };
  if (!header.alg || !allowedAlgs.includes(header.alg)) {
    throw new Error(`alg not allowed: ${header.alg}`);
  }
  const digest = sha256(Buffer.from(`${parts[0]}.${parts[1]}`, 'utf8'));
  const sig = Buffer.from(parts[2], 'base64url');
  const ok = p256.verify(sig.subarray(0, 64), digest, pubUncompressed, { lowS: false });
  if (!ok) throw new Error('signature verification failed');
  return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
}

export function peekHeader(token: string): Record<string, unknown> {
  const [h] = token.split('.');
  return JSON.parse(Buffer.from(h, 'base64url').toString('utf8'));
}

export { P256Provider };
