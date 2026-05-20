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
