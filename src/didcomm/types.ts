export interface JWE {
  protected: string;
  iv: string;
  ciphertext: string;
  tag: string;
}

export interface DecryptJWEResult {
  protected: Record<string, unknown>;
  plaintext: string;
  json: Record<string, unknown> | null;
}
