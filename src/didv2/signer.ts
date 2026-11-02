import { SigningKey, computeAddress, getBytes, hexlify } from 'ethers';
import { normalizeHex } from '../common/crypto/hex';

export interface SignerProvider {
  sign(payload: Uint8Array): Promise<Uint8Array> | Uint8Array;
  getAddress(): string;
}

export class DefaultProvider implements SignerProvider {
  private readonly key: SigningKey;

  constructor(privateKeyHex: string) {
    this.key = new SigningKey(`0x${normalizeHex(privateKeyHex)}`);
  }

  sign(hashPayload: Uint8Array): Uint8Array {
    if (hashPayload.length !== 32) {
      throw new Error('failed to sign payload: digest must be 32 bytes');
    }
    const sig = this.key.sign(hexlify(hashPayload));
    const compact = getBytes(sig.serialized);
    if (compact.length !== 65) {
      throw new Error(`invalid signature length: expected 65 bytes, got ${compact.length}`);
    }
    return compact;
  }

  getAddress(): string {
    return computeAddress(this.key.publicKey).toLowerCase();
  }
}

export function newDefaultProvider(privHex: string): DefaultProvider {
  return new DefaultProvider(privHex);
}
