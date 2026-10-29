/**
 * Shared types for the VC package — mirrors the Go credential structs.
 */
import type { Proof } from '../common/dto/proof';
import type { JSONMap } from '../common/util/json';
import type { ResolverProvider } from '../common/verification-method';
import type { DecoyConfig } from '../common/sdjwt';
import type { SignerProvider } from '../common/signer/signer';

export type CredentialData = JSONMap;

export interface Status {
  id?: string;
  type: string;
  statusPurpose?: string;
  statusListIndex?: string;
  statusListCredential?: string;
}

export interface Subject {
  id?: string;
  customFields?: Record<string, unknown>;
}

export interface Schema {
  id?: string;
  type?: string;
}

export interface CredentialContents {
  context?: unknown[];
  id?: string;
  types?: string[];
  issuer?: string;
  validFrom?: Date;
  validUntil?: Date;
  credentialStatus?: Status[];
  subject?: Subject[];
  schemas?: Schema[];
}

export type Decoy = DecoyConfig;

export type SchemaLoaderFunc = (schemaID: string) => Promise<Uint8Array> | Uint8Array;

export interface CredentialOptions {
  /** Validate against JSON schemas referenced via credentialSchema. */
  validateSchema?: boolean;
  /** Cryptographically verify the proof. */
  verifyProof?: boolean;
  /** Check validFrom/validUntil against the current clock. */
  checkExpiration?: boolean;
  /** Clock skew tolerance in milliseconds when checking dates and JWT time claims. */
  clockSkewLeewayMs?: number;
  /** Check the credentialStatus list bit. */
  checkRevocation?: boolean;
  /** DID base URL — used to construct the default HTTPResolver when no
   *  resolver option is supplied. */
  didBaseURL?: string;
  /** Verification method fragment ("key-2") or full DID URL. */
  verificationMethodKey?: string;
  /** Pre-computed SD-JWT disclosures to append at serialization time. */
  sdDisclosures?: string[];
  /** Paths the issuer wants to make selectively disclosable. */
  sdSelectivePaths?: string[];
  /** Hash algorithm for SD-JWT (sha-256 default). */
  sdAlg?: string;
  /** Shuffle `_sd` arrays to obscure disclosure order. */
  sdShuffle?: boolean;
  /** Decoy digests to inject for SD-JWT privacy. */
  sdDecoys?: Decoy[];
  /** Custom schema loader (e.g. cached / file-based). */
  schemaLoader?: SchemaLoaderFunc;
  /** Custom DID resolver. Defaults to HTTPResolver(didBaseURL). */
  resolver?: ResolverProvider;
}

/** Shared interface implemented by JWTCredential and JSONCredential. */
export interface Credential {
  addProof(priv: string, opts?: CredentialOptions): Promise<void>;
  addProofByProvider(signer: SignerProvider, opts?: CredentialOptions): Promise<void>;
  addCustomProof(proof: Proof, opts?: CredentialOptions): Promise<void>;
  getSigningInput(): Promise<Uint8Array>;
  verify(opts?: CredentialOptions): Promise<void>;
  serialize(): Promise<unknown>;
  getContents(): Uint8Array;
  getType(): 'JWT' | 'JSON';
  extractField(path: string): unknown;
  addSelectiveDisclosures(selectivePaths: string[]): Promise<Credential>;
}
