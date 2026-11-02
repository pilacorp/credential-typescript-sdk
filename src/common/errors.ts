/** Shared error categories so callers need not match message strings. */
export const ErrorCode = {
  AudienceUnbound: 'audience_unbound',
  ChallengeMismatch: 'challenge_mismatch',
  DomainMismatch: 'domain_mismatch',
  Unsigned: 'unsigned',
  NoDisclosures: 'no_disclosures',
  InvalidProof: 'invalid_proof',
  MalformedInput: 'malformed_input',
  Unsupported: 'unsupported',
} as const;

export type ErrorCodeValue = (typeof ErrorCode)[keyof typeof ErrorCode];

export class CredentialError extends Error {
  readonly code: ErrorCodeValue;

  constructor(code: ErrorCodeValue, message: string) {
    super(message);
    this.name = 'CredentialError';
    this.code = code;
  }
}
