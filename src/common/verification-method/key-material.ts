/**
 * Public key material helpers — Node port of
 * credential/common/verification-method/key_material.go
 */
import { secp256k1 } from '@noble/curves/secp256k1';
import { bytesToHex } from '../crypto/hex';
import type { JWK, VerificationMethodEntry } from './verification-method';

export function publicKeyHexFromVM(vm: VerificationMethodEntry | null): string {
  if (!vm) throw new Error('verification method is nil');
  if (vm.publicKeyHex) {
    return vm.publicKeyHex.replace(/^0x/i, '');
  }
  if (vm.publicKeyJwk) {
    return jwkToHex(vm.publicKeyJwk);
  }
  throw new Error(`verification method '${vm.id}' has no public key material`);
}

/**
 * Convert a secp256k1 JWK to uncompressed hex (0x04 || X || Y).
 */
export function jwkToHex(jwk: JWK): string {
  if (jwk.kty !== 'EC') throw new Error(`unsupported key type: ${jwk.kty}`);
  if (jwk.crv !== 'secp256k1') throw new Error(`unsupported curve: ${jwk.crv}`);

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
  // Sanity-check against curve order via @noble (will throw if invalid)
  secp256k1.ProjectivePoint.fromHex(uncompressed);
  return bytesToHex(uncompressed);
}
