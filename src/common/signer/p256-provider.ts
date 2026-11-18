import { p256 } from '@noble/curves/nist';
import { SignFunc, SignerProvider, AlgorithmProvider, validateSignatureLength } from './signer';
import { hexToBytes, normalizeHex } from '../crypto/hex';

const P256_N = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');

function checkP256Sig(bytes: Uint8Array): Uint8Array {
  if (bytes.length !== 64) {
    throw new Error(`ecdsa-rdfc-2019 expects a 64-byte P-256 signature, got ${bytes.length}`);
  }
  validateSignatureLength(bytes);
  return bytes;
}

/**
 * Signs a 32-byte digest with a P-256 key (ecdsa-sd-2023), producing a 64-byte
 * R||S signature. Built from an in-memory key (hex string or 32 raw bytes) or a
 * callback (HSM/KMS, via P256Provider.fromFunc / newP256Func) that receives the digest and returns the 64-byte signature.
 */
export class P256Provider<R extends Uint8Array | Promise<Uint8Array> = Uint8Array>
  implements SignerProvider, AlgorithmProvider
{
  private readonly privKey?: Uint8Array;
  private readonly signFn?: SignFunc;

  constructor(key: string | Uint8Array);
  constructor(key: string | Uint8Array | SignFunc) {
    if (typeof key === 'function') {
      this.signFn = key;
      return;
    }
    const raw = typeof key === 'string' ? hexToBytes(normalizeHex(key)) : new Uint8Array(key);
    if (raw.length !== 32) {
      throw new Error(`P-256 private key must be 32 bytes, got ${raw.length}`);
    }
    const d = BigInt('0x' + Buffer.from(raw).toString('hex'));
    if (d <= 0n || d >= P256_N) {
      throw new Error('P-256 private key must satisfy 1 <= d < curve order');
    }
    this.privKey = raw;
  }

  /** A callback-backed provider (HSM/KMS): sign may return a Promise. */
  static fromFunc(signFn: SignFunc): P256Provider<Uint8Array | Promise<Uint8Array>> {
    if (!signFn) throw new Error('sign function is nil');
    return new P256Provider<Uint8Array | Promise<Uint8Array>>(signFn as never);
  }

  sign(hashPayload: Uint8Array): R {
    if (hashPayload.length !== 32) {
      throw new Error(`hash payload must be 32 bytes, got ${hashPayload.length}`);
    }
    if (this.signFn) {
      const out = this.signFn(hashPayload);
      return (out instanceof Uint8Array ? checkP256Sig(out) : out.then(checkP256Sig)) as R;
    }
    return checkP256Sig(p256.sign(hashPayload, this.privKey!, { lowS: true }).toCompactRawBytes()) as R;
  }

  /** The uncompressed public key (04||X||Y), or undefined for a callback-backed provider. */
  publicKeyUncompressed(): Uint8Array | undefined {
    return this.privKey ? p256.getPublicKey(this.privKey, false) : undefined;
  }

  /** JOSE algorithm for P-256 JsonWebSignature2020. */
  algorithm(): string {
    return 'ES256';
  }
}

/** P-256 signer from an in-memory key (hex string or 32 raw bytes). */
export function newP256Provider(key: string | Uint8Array): P256Provider {
  return new P256Provider(key);
}

/** P-256 signer that delegates to `signFn`, which gets the 32-byte digest and returns 64-byte R||S. */
export function newP256Func(signFn: SignFunc): P256Provider<Uint8Array | Promise<Uint8Array>> {
  return P256Provider.fromFunc(signFn);
}
