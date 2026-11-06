/**
 * Signer abstraction — Node port of credential/common/signer/signer.go
 *
 * Contract:
 *  - hashPayload MUST be a 32-byte digest computed by the SDK.
 *  - Implementations may return:
 *    - 64 bytes: R(32) || S(32)
 *    - 65 bytes: R(32) || S(32) || V(1)
 */
export interface SignerProvider {
  sign(hashPayload: Uint8Array): Promise<Uint8Array> | Uint8Array;
}

export function validateSignatureLength(signature: Uint8Array): void {
  if (signature.length !== 64 && signature.length !== 65) {
    throw new Error(
      `invalid signature length: got ${signature.length}, want 64 or 65`,
    );
  }
}

/**
 * Lets a signer declare its JOSE algorithm for JsonWebSignature2020 (RSA).
 * Signers that don't implement it default to "RS256".
 */
export interface AlgorithmProvider {
  algorithm(): string;
}

/** The JOSE algorithm a provider declares, defaulting to "RS256". */
export function algorithmOf(p: SignerProvider): string {
  const a = p as Partial<AlgorithmProvider>;
  return typeof a.algorithm === 'function' ? a.algorithm() : 'RS256';
}

/** The JOSE `alg` for the key a verification method holds ('RSA' uses the provider's declared algorithm). */
export function algForKeyKind(kind: 'secp256k1' | 'P-256' | 'RSA', provider?: SignerProvider): string {
  switch (kind) {
    case 'secp256k1':
      return 'ES256K';
    case 'P-256':
      return 'ES256';
    case 'RSA':
      return provider ? algorithmOf(provider) : 'RS256';
    default:
      throw new Error(`no JOSE algorithm for key kind ${String(kind)}`);
  }
}

export type SignFunc = (digest: Uint8Array) => Promise<Uint8Array> | Uint8Array;
