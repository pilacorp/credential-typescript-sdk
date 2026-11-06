/**
 * Public key material helpers — Node port of
 * credential/common/verification-method/key_material.go
 */
import { p256, p384 } from '@noble/curves/nist';
import { secp256k1 } from '@noble/curves/secp256k1';
import { bytesToHex, hexToBytes } from '../crypto/hex';
import type { JWK, VerificationMethodEntry } from './verification-method';
import { decodeECPublicMultibase } from './multikey';

export function publicKeyHexFromVM(vm: VerificationMethodEntry | null): string {
  if (!vm) throw new Error('verification method is nil');
  if (vm.publicKeyHex) {
    // Like Go's ECPubFromVM: publicKeyHex names no curve so it is read as
    // secp256k1 whatever the VM type says, and the point must be valid.
    const hex = vm.publicKeyHex.replace(/^0x/i, '');
    const raw = hexToBytes(hex);
    if (!((raw.length === 33 && (raw[0] === 2 || raw[0] === 3)) || (raw.length === 65 && raw[0] === 4))) {
      throw new Error(`secp256k1 public key: want 33 compressed or 65 uncompressed bytes, got ${raw.length}`);
    }
    try {
      secp256k1.ProjectivePoint.fromHex(raw);
    } catch (e) {
      throw new Error(`invalid secp256k1 public key: ${(e as Error).message}`);
    }
    return hex;
  }
  if (vm.publicKeyJwk) {
    return jwkToHex(vm.publicKeyJwk);
  }
  if (vm.publicKeyMultibase) {
    return bytesToHex(decodeECPublicMultibase(vm.publicKeyMultibase).uncompressed);
  }
  throw new Error(`verification method '${vm.id}' has no public key material`);
}

/**
 * Convert an EC JWK (secp256k1, P-256 or P-384) to uncompressed hex (0x04 || X || Y).
 */
export function jwkToHex(jwk: JWK): string {
  if (jwk.kty !== 'EC') throw new Error(`unsupported key type: ${jwk.kty}`);
  if (jwk.crv !== 'secp256k1' && jwk.crv !== 'P-256' && jwk.crv !== 'P-384') {
    throw new Error(`unsupported curve: ${jwk.crv} (want secp256k1, P-256 or P-384)`);
  }
  if (!jwk.x || !jwk.y) throw new Error('JWK x/y are required');

  if (jwk.crv === 'P-384') return p384JwkToHex(jwk.x, jwk.y);
  const x = Buffer.from(jwk.x, 'base64url');
  const y = Buffer.from(jwk.y, 'base64url');
  if (x.length !== 32 || y.length !== 32) {
    throw new Error('JWK x/y must each decode to 32 bytes');
  }
  // Build uncompressed point so callers can hand it directly to verifiers
  // that expect either form.
  const uncompressed = new Uint8Array(65);
  uncompressed[0] = 0x04;
  uncompressed.set(x, 1);
  uncompressed.set(y, 33);
  // Sanity-check against the curve (throws if the point is invalid).
  if (jwk.crv === 'P-256') p256.ProjectivePoint.fromHex(uncompressed);
  else secp256k1.ProjectivePoint.fromHex(uncompressed);
  return bytesToHex(uncompressed);
}

/** Go ECPubFromJWK on P-384: short coordinates are left-padded, longer than 48 bytes refused. */
function p384JwkToHex(xb64: string, yb64: string): string {
  const x = Buffer.from(xb64, 'base64url');
  const y = Buffer.from(yb64, 'base64url');
  if (x.length > 48 || y.length > 48) {
    throw new Error(`jwk P-384: coordinates must be at most 48 bytes, got x=${x.length} y=${y.length}`);
  }
  const pt = new Uint8Array(97);
  pt[0] = 0x04;
  pt.set(x, 49 - x.length);
  pt.set(y, 97 - y.length);
  try {
    p384.ProjectivePoint.fromHex(pt).assertValidity();
  } catch (e) {
    throw new Error(`jwk P-384: invalid public key point: ${(e as Error).message}`);
  }
  return bytesToHex(pt);
}
