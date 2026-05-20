/**
 * Revocation reason taxonomy — Node port of
 * credential/common/verification-method/revocation.go
 *
 * "Soft" reasons (e.g. superseded) keep proofs created BEFORE the revoked
 * timestamp valid. "Hard" reasons (keyCompromise) invalidate every signature.
 */

export const ReasonSuperseded = 'superseded';
export const ReasonKeyCompromise = 'keyCompromise';

export function isHardRevocationReason(reason?: string): boolean {
  return reason === ReasonKeyCompromise;
}
