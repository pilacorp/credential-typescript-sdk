import type { Proof } from '../common/dto/proof';
import type { JSONMap } from '../common/util/json';
import type { ResolverProvider } from '../common/verification-method';
import type { SignerProvider } from '../common/signer/signer';
import type { Credential, CredentialOptions } from '../vc/types';

export type PresentationData = JSONMap;

export interface PresentationContents {
  context?: unknown[];
  id?: string;
  types?: string[];
  holder?: string;
  validFrom?: Date;
  validUntil?: Date;
  verifiableCredentials?: Credential[];
}

export interface PresentationOptions {
  /** Verify the embedded credentials. `true` verifies their proofs; pass
   *  CredentialOptions to forward verification options (go WithVCValidation(opts...)).
   *  The presentation's resolver and leeway are applied first, so options given
   *  here win. */
  validateVC?: boolean | CredentialOptions;
  verifyProof?: boolean;
  checkExpiration?: boolean;
  /** Clock skew tolerance in milliseconds when checking dates and JWT time claims. */
  clockSkewLeewayMs?: number;
  didBaseURL?: string;
  verificationMethodKey?: string;
  resolver?: ResolverProvider;
  /** Signing: JWT `nonce` / JSON-LD `proof.challenge`. */
  challenge?: string;
  /** Signing: JWT `aud` / JSON-LD `proof.domain`. */
  domain?: string;
  /** Verifying: required nonce/challenge. Implies verifyProof. */
  expectedChallenge?: string;
  /** Verifying: required aud/domain. Implies verifyProof. */
  expectedDomain?: string;
  /** Verifying: reject presentations with no audience unless expectedDomain is set. */
  requireAudience?: boolean;
  /** Verifying a JSON-LD proof set: check only the proof bound to this VM URL. */
  proofVerificationMethod?: string;
  /** Signing a JWT/JOSE presentation: replace a signature already present. Refused on JSON-LD. */
  replaceProof?: boolean;
}

/** Read-only consumer contract (go vp.Presentation). */
export interface Presentation {
  verify(opts?: PresentationOptions): Promise<void>;
  serialize(): Promise<unknown>;
  getContents(): Uint8Array;
  getType(): 'JWT' | 'JSON' | 'JOSE';
  extractField(path: string): unknown;
}

/** A presentation that can also be signed. */
export interface SignablePresentation extends Presentation {
  addProof(priv: string, opts?: PresentationOptions): Promise<void>;
  addProofByProvider(signer: SignerProvider, opts?: PresentationOptions): Promise<void>;
  addCustomProof(proof: Proof, opts?: PresentationOptions): Promise<void>;
  getSigningInput(): Promise<Uint8Array>;
}
