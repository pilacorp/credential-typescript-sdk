/**
 * secp256k1 crypto primitives — Node port of credential/common/crypto/crypto.go
 *
 * Provides:
 *  - Raw secp256k1 sign/verify of arbitrary payloads
 *  - JSON-canonicalized verification (RFC 8785 + sha256)
 *
 * Recovery byte (V) is appended when signing so legacy proofs that include it
 * remain interoperable. Verification accepts both 64- and 65-byte signatures.
 */
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { transform } from '../jsoncanonicalizer/jsoncanonicalizer';
import { bytesToHex, hexToBytes, keyToBytes, normalizeHex } from './hex';

export function signMessage(privateKey: Uint8Array, message: Uint8Array): string {
  if (privateKey.length !== 32) {
    throw new Error('private key must be 32 bytes');
  }
  const hash = sha256(message);
  const sig = secp256k1.sign(hash, privateKey, { lowS: true });
  const r = sig.r.toString(16).padStart(64, '0');
  const s = sig.s.toString(16).padStart(64, '0');
  const recovery = sig.recovery ?? 0;
  const out = new Uint8Array(65);
  out.set(hexToBytes(r), 0);
  out.set(hexToBytes(s), 32);
  out[64] = recovery;
  return bytesToHex(out);
}

export function verifyJSONSignature(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  let canonical: Uint8Array;
  try {
    canonical = transform(message);
  } catch {
    return false;
  }
  return verifySignature(publicKey, canonical, signature);
}

export function verifySignature(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  // Mirrors Go VerifySignature: a 65-byte signature is checked by recovering
  // the key from its recovery id; anything else must be 64 bytes, low-S.
  if (publicKey.length !== 33 || message.length === 0) {
    return false;
  }
  const hash = sha256(message);
  try {
    if (signature.length === 65) {
      const v = signature[64];
      if (v > 3) return false;
      const sig = secp256k1.Signature.fromCompact(signature.subarray(0, 64)).addRecoveryBit(v);
      const recovered = sig.recoverPublicKey(hash).toRawBytes(true);
      return Buffer.from(recovered).equals(Buffer.from(publicKey));
    }
    if (signature.length !== 64) return false;
    return secp256k1.verify(signature, hash, publicKey, { lowS: true });
  } catch {
    return false;
  }
}

/**
 * Verify an ECDSA signature where the supplied digest is the message to verify
 * directly (no SHA-256 wrapping). Matches the Go `ECDSAVerifySignature` used
 * for DataIntegrityProof / ecdsa-rdfc-2019.
 */
export function ecdsaVerifySignature(
  publicKeyHex: string,
  signatureHex: string,
  msg: Uint8Array,
): boolean {
  let pubBytes = hexToBytes(publicKeyHex);
  let pubKey: Uint8Array;
  if (pubBytes.length === 33 && (pubBytes[0] === 0x02 || pubBytes[0] === 0x03)) {
    // compressed → derive uncompressed using @noble/curves point recovery
    const point = secp256k1.ProjectivePoint.fromHex(pubBytes);
    pubKey = point.toRawBytes(false); // uncompressed
  } else if (pubBytes.length === 65 && pubBytes[0] === 0x04) {
    pubKey = pubBytes;
  } else if (pubBytes.length === 64) {
    pubKey = new Uint8Array(65);
    pubKey[0] = 0x04;
    pubKey.set(pubBytes, 1);
  } else {
    throw new Error('unsupported public key format');
  }

  const sigBytes = hexToBytes(signatureHex);
  let rs: Uint8Array;
  if (sigBytes.length === 65) {
    rs = sigBytes.subarray(0, 64);
  } else if (sigBytes.length === 64) {
    rs = sigBytes;
  } else {
    throw new Error(
      `invalid signature length: got ${sigBytes.length}, want 64 or 65 bytes`,
    );
  }

  // Verify against raw `msg` (no hashing) so callers control digest derivation.
  // @noble exposes verify(sig, msg, pub) where msg is the raw digest bytes.
  return secp256k1.verify(rs, msg, pubKey, { lowS: false });
}

export function verifyKeyPairFromHex(privHex: string, pubHex: string): boolean {
  const priv = hexToBytes(normalizeHex(privHex));
  if (priv.length !== 32) return false;
  const derived = secp256k1.getPublicKey(priv, false); // uncompressed
  let target = hexToBytes(normalizeHex(pubHex));
  if (target.length === 33 && (target[0] === 0x02 || target[0] === 0x03)) {
    const point = secp256k1.ProjectivePoint.fromHex(target);
    target = point.toRawBytes(false);
  }
  if (target.length !== derived.length) return false;
  for (let i = 0; i < target.length; i++) {
    if (target[i] !== derived[i]) return false;
  }
  return true;
}

export { hexToBytes, bytesToHex, keyToBytes, normalizeHex };
