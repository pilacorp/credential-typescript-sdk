/**
 * ES256K signing method — Node port of credential/common/jwt/signing_method.go
 *
 * Signs a string with SHA-256(string) → secp256k1 sign, returning R||S (64 bytes).
 */
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { hexToBytes, normalizeHex } from '../crypto/hex';

export interface SigningMethod {
  alg(): string;
  sign(signingString: string, key: unknown): Uint8Array;
  verify(signingString: string, signature: Uint8Array, key: unknown): void;
}

class SigningMethodES256K implements SigningMethod {
  alg(): string {
    return 'ES256K';
  }

  sign(signingString: string, key: unknown): Uint8Array {
    if (typeof key !== 'string') throw new Error('invalid key type');
    const privKey = hexToBytes(normalizeHex(key));
    if (privKey.length !== 32) throw new Error('invalid private key');

    const hash = sha256(Buffer.from(signingString, 'utf8'));
    const sig = secp256k1.sign(hash, privKey, { lowS: true });
    const r = sig.r.toString(16).padStart(64, '0');
    const s = sig.s.toString(16).padStart(64, '0');
    const out = new Uint8Array(64);
    out.set(hexToBytes(r), 0);
    out.set(hexToBytes(s), 32);
    return out;
  }

  verify(signingString: string, signature: Uint8Array, key: unknown): void {
    if (signature.length !== 64) throw new Error('invalid signature length');
    const hash = sha256(Buffer.from(signingString, 'utf8'));
    if (!isUncompressedOrCompressedPubKey(key)) {
      throw new Error('invalid key type');
    }
    const pub = key as Uint8Array;
    if (!secp256k1.verify(signature, hash, pub, { lowS: false })) {
      throw new Error('signature verification failed');
    }
  }
}

function isUncompressedOrCompressedPubKey(k: unknown): k is Uint8Array {
  return k instanceof Uint8Array;
}

export const ES256K: SigningMethod = new SigningMethodES256K();
