/**
 * Linked Data Proof for a Verifiable Credential.
 * Mirrors Go: credential/common/dto/proof.go
 */
export interface Proof {
  type: string;
  created: string;
  verificationMethod: string;
  proofPurpose: string;
  proofValue?: string;
  jws?: string;
  disclosures?: string[];
  cryptosuite?: string;
  challenge?: string;
  domain?: string;
  /** For JWT external signing workflow (raw signature bytes) */
  signature?: Uint8Array;
}
