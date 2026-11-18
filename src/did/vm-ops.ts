/**
 * Compatibility aliases: the verification-method operations now live under the
 * didv2 namespace (src/didv2/vm-ops.ts), mirroring Go's didv2/did.DIDDocument methods.
 */
export {
  addVerificationMethod,
  addVerificationMethodPurposes,
  removeVerificationMethodPurposes,
  revokeVerificationMethod,
  rotateVerificationMethod,
} from '../didv2/vm-ops';
export { canonicalVMID as canonicalVmId, findVerificationMethod } from '../didv2/document';
export type { VerificationPurpose } from '../didv2/types';
