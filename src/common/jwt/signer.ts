/**
 * JWT signer — Node port of credential/common/jwt/signer.go
 *
 * Uses a pluggable SignerProvider so the same code path supports in-memory
 * keys (DefaultProvider) and remote signers (Vault/HSM/KMS).
 */
import { sha256 } from '@noble/hashes/sha256';
import { SignerProvider, validateSignatureLength } from '../signer/signer';

export class JWTSigner {
  constructor(private readonly signer: SignerProvider | null) {}

  async signString(signingString: string): Promise<string> {
    if (!this.signer) throw new Error('jwt signer: signer cannot be nil');
    const hash = sha256(Buffer.from(signingString, 'utf8'));
    let signature = await this.signer.sign(hash);
    validateSignatureLength(signature);
    if (signature.length === 65) signature = signature.subarray(0, 64);
    return Buffer.from(signature).toString('base64url');
  }
}

export function newJWTSigner(signer: SignerProvider): JWTSigner {
  return new JWTSigner(signer);
}
