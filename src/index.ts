/**
 * Public entry point for the credential SDK.
 *
 * The package mirrors the Go `credential` module:
 *
 *   import { vc, vp, signer } from '@pilacorp/credential-sdk';
 *
 * Or use the named sub-modules directly via deep imports
 * (`@pilacorp/credential-sdk/dist/vc/credential`).
 */
export * as vc from './vc/credential';
export * as vp from './vp/presentation';
export * as did from './did';
export * as didcomm from './didcomm';
export * as sdjwt from './common/sdjwt';
export * as verificationMethod from './common/verification-method';
export * as credentialStatus from './common/credential-status';
export * as jsoncanonicalizer from './common/jsoncanonicalizer/jsoncanonicalizer';

// Convenience re-exports for the common DTO / signer interfaces.
export type { Proof } from './common/dto/proof';
export type { SignerProvider } from './common/signer/signer';
export { DefaultProvider } from './common/signer/default-provider';
export { P256Provider } from './common/signer/p256-provider';
