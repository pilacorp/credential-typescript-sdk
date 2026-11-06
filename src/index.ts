/**
 * Public entry point for the credential SDK.
 *
 * Namespaces mirror the Go packages (vc, vp, did, didv2, signer, ...):
 *
 *   import { vc, vp, signer, didv2 } from '@pilacorp/credential-sdk';
 *
 * Or use the named sub-modules directly via deep imports
 * (`@pilacorp/credential-sdk/dist/vc/credential`).
 */
export * as vc from './vc/credential';
export * as vp from './vp/presentation';
export * as did from './did';
export * as didcomm from './didcomm';
export * as sdjwt from './common/sdjwt';
export * as signer from './common/signer';
export * as verificationMethod from './common/verification-method';
export * as credentialStatus from './common/credential-status';
export * as jsoncanonicalizer from './common/jsoncanonicalizer/jsoncanonicalizer';
export * as processor from './common/processor/processor';
export * as digitalcredential from './digitalcredential';
export * as didv2 from './didv2';

// Convenience re-exports for the common DTO / signer interfaces.
export type { Proof } from './common/dto/proof';
export type { SignerProvider } from './common/signer/signer';
export { DefaultProvider } from './common/signer/default-provider';
export { P256Provider } from './common/signer/p256-provider';
export { RSAProvider } from './common/signer/rsa-provider';
export type { AlgorithmProvider } from './common/signer/signer';
export { CredentialError, ErrorCode } from './common/errors';
export * as ecdsasd from './common/ecdsasd';
export {
  JOSECredential,
  TypeVCJWT,
  TypeVCSDJWT,
} from './vc/jose-credential';
export { ECDSASDCredential } from './vc/ecdsasd-credential';
export {
  generateDualCurveKeyPair,
  generateP256KeyPair,
  validateDidDocument,
  addVerificationMethod,
  rotateVerificationMethod,
  revokeVerificationMethod,
  addVerificationMethodPurposes,
  removeVerificationMethodPurposes,
} from './did';
export {
  StatusListClient,
  bitAt,
  isRevoked,
  isStatusSet,
  newStatusListClient,
} from './common/credential-status';
export {
  registerContext,
  withDocumentLoader,
  bundledContextUrls,
} from './common/processor/processor';
