import { SignFunc, SignerProvider, AlgorithmProvider } from './signer';

/**
 * Signs a digest for JsonWebSignature2020 (RSA) through a caller-supplied
 * callback (HSM/KMS). The JOSE algorithm is declared via algorithm() so the SDK
 * hashes the signing input with the matching SHA and writes the JWS header.
 * ponytail: no in-memory-key constructor (Go's NewRSAProvider); node:crypto cannot
 * sign a pre-hashed digest with PSS, add when an RSA signing consumer exists.
 */
export class RSAProvider implements SignerProvider, AlgorithmProvider {
  private readonly alg: string;

  constructor(private readonly signFn: SignFunc, alg = 'RS256') {
    if (!signFn) throw new Error('sign function is nil');
    this.alg = alg || 'RS256';
  }

  sign(digest: Uint8Array): Promise<Uint8Array> | Uint8Array {
    return this.signFn(digest);
  }

  algorithm(): string {
    return this.alg;
  }
}

/** RSA JWS signer delegating to `signFn`, which gets the digest (already hashed with alg's SHA) and returns the raw signature. */
export function newRSAFunc(signFn: SignFunc, alg = 'RS256'): RSAProvider {
  return new RSAProvider(signFn, alg);
}
