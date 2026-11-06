/**
 * Public key material helpers — Node port of
 * credential/common/verification-method/key_material.go
 */
import { p256 } from '@noble/curves/nist';
import { secp256k1 } from '@noble/curves/secp256k1';
import { bytesToHex, hexToBytes } from '../crypto/hex';
import type { JWK, VerificationMethodEntry } from './verification-method';
import { decodeP256PublicMultibase } from './multikey';

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
    return bytesToHex(decodeP256PublicMultibase(vm.publicKeyMultibase));
  }
  throw new Error(`verification method '${vm.id}' has no public key material`);
}

/**
 * Convert an EC JWK (secp256k1 or P-256) to uncompressed hex (0x04 || X || Y).
 */
export function jwkToHex(jwk: JWK): string {
  if (jwk.kty !== 'EC') throw new Error(`unsupported key type: ${jwk.kty}`);
  if (jwk.crv !== 'secp256k1' && jwk.crv !== 'P-256') {
    throw new Error(`unsupported curve: ${jwk.crv}`);
  }
  if (!jwk.x || !jwk.y) throw new Error('JWK x/y are required');

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
