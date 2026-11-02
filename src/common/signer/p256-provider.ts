import { p256 } from '@noble/curves/nist';
import { SignerProvider, validateSignatureLength } from './signer';
import { hexToBytes, normalizeHex } from '../crypto/hex';

const P256_N = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');

export class P256Provider implements SignerProvider {
  private readonly privKey: Uint8Array;

  constructor(privHex: string) {
    const raw = hexToBytes(normalizeHex(privHex));
    if (raw.length !== 32) {
      throw new Error(`P-256 private key must be 32 bytes, got ${raw.length}`);
    }
    const d = BigInt('0x' + Buffer.from(raw).toString('hex'));
    if (d <= 0n || d >= P256_N) {
      throw new Error('P-256 private key must satisfy 1 <= d < curve order');
    }
    this.privKey = raw;
  }

  sign(hashPayload: Uint8Array): Uint8Array {
    if (hashPayload.length !== 32) {
      throw new Error(`hash payload must be 32 bytes, got ${hashPayload.length}`);
    }
    const sig = p256.sign(hashPayload, this.privKey, { lowS: true });
    const bytes = sig.toCompactRawBytes();
    if (bytes.length !== 64) {
      throw new Error(`ecdsa-rdfc-2019 expects a 64-byte P-256 signature, got ${bytes.length}`);
    }
    validateSignatureLength(bytes);
    return bytes;
  }

  publicKeyUncompressed(): Uint8Array {
    return p256.getPublicKey(this.privKey, false);
  }
}
