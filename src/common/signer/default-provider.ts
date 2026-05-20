/**
 * In-memory secp256k1 signer — Node port of credential/common/signer/default_provider.go
 *
 * Uses @noble/curves secp256k1 with deterministic K (RFC 6979) so signatures
 * are byte-for-byte reproducible across implementations.
 *
 * Returns 65 bytes: R(32) || S(32) || V(1) to match Ethereum's signing format,
 * which the verifier path expects when handling legacy proofs.
 */
import { secp256k1 } from '@noble/curves/secp256k1';
import { SignerProvider, validateSignatureLength } from './signer';
import { hexToBytes, normalizeHex } from '../crypto/hex';

export class DefaultProvider implements SignerProvider {
  private readonly privKey: Uint8Array;

  constructor(privHex: string) {
    const hex = normalizeHex(privHex);
    const raw = hexToBytes(hex);
    if (raw.length !== 32) {
      throw new Error(`private key must be 32 bytes, got ${raw.length}`);
    }
    this.privKey = raw;
  }

  sign(hashPayload: Uint8Array): Uint8Array {
    if (hashPayload.length !== 32) {
      throw new Error(
        `hash payload must be 32 bytes, got ${hashPayload.length}`,
      );
    }
    const sig = secp256k1.sign(hashPayload, this.privKey, { lowS: true });
    const r = sig.r.toString(16).padStart(64, '0');
    const s = sig.s.toString(16).padStart(64, '0');
    const recovery = sig.recovery ?? 0;
    const combined = new Uint8Array(65);
    combined.set(hexToBytes(r), 0);
    combined.set(hexToBytes(s), 32);
    combined[64] = recovery;
    validateSignatureLength(combined);
    return combined;
  }
}

export function newDefaultProvider(privHex: string): DefaultProvider {
  return new DefaultProvider(privHex);
}
