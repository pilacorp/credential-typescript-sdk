import { createPublicKey, verify as cryptoVerify, constants } from 'node:crypto';
import { p256 } from '@noble/curves/nist';
import { sha256 } from '@noble/hashes/sha256';
import { sha384, sha512 } from '@noble/hashes/sha512';
import type { JWK } from '../verification-method/verification-method';

export function hashForJWSAlg(alg: string, input: Uint8Array): Uint8Array {
  switch (alg) {
    case 'ES256':
    case 'RS256':
    case 'PS256':
      return sha256(input);
    case 'RS384':
    case 'PS384':
      return sha384(input);
    case 'RS512':
    case 'PS512':
      return sha512(input);
    default:
      throw new Error(`unsupported JWS alg: ${alg}`);
  }
}

export function p256PubFromJwk(jwk: JWK): Uint8Array {
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') {
    throw new Error('expected P-256 EC JWK');
  }
  if (!jwk.x || !jwk.y) throw new Error('P-256 JWK missing x/y');
  const x = Buffer.from(jwk.x, 'base64url');
  const y = Buffer.from(jwk.y, 'base64url');
  const uncompressed = new Uint8Array(65);
  uncompressed[0] = 0x04;
  uncompressed.set(x, 1);
  uncompressed.set(y, 33);
  return p256.ProjectivePoint.fromHex(uncompressed).toRawBytes(false);
}

export function verifyES256(pubUncompressed: Uint8Array, digest: Uint8Array, sig: Uint8Array): boolean {
  try {
    return p256.verify(sig.subarray(0, 64), digest, pubUncompressed, { lowS: false });
  } catch {
    return false;
  }
}

export function verifyRSAJWS(alg: string, jwk: JWK, signingInput: Uint8Array, sig: Uint8Array): void {
  if (jwk.kty !== 'RSA' || !jwk.n || !jwk.e) throw new Error('parse RSA jwk: missing n/e');
  const key = createPublicKey({
    key: { kty: 'RSA', n: jwk.n, e: jwk.e },
    format: 'jwk',
  });
  const pss = alg.startsWith('PS');
  const hash = alg.endsWith('384') ? 'sha384' : alg.endsWith('512') ? 'sha512' : 'sha256';
  const ok = cryptoVerify(
    hash,
    Buffer.from(signingInput),
    pss
      ? { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST }
      : { key, padding: constants.RSA_PKCS1_PADDING },
    Buffer.from(sig),
  );
  if (!ok) throw new Error(`JsonWebSignature2020 ${alg} signature verification failed`);
}
