export const Code = {
  Malformed: 'MALFORMED',
  TypInvalid: 'TYP_INVALID',
  IssuerNotSupported: 'ISSUER_NOT_SUPPORTED',
  IssuerNotAccepted: 'ISSUER_NOT_ACCEPTED',
  IssuerKeyNotFound: 'ISSUER_KEY_NOT_FOUND',
  IssuerKeyUnavailable: 'ISSUER_KEY_UNAVAILABLE',
  AlgNotAllowed: 'ALG_NOT_ALLOWED',
  SignatureInvalid: 'SIGNATURE_INVALID',
  DisclosureInvalid: 'DISCLOSURE_INVALID',
  Expired: 'EXPIRED',
  NotYetValid: 'NOT_YET_VALID',
  AudienceMismatch: 'AUDIENCE_MISMATCH',
  VCTNotAccepted: 'VCT_NOT_ACCEPTED',
  KBMissing: 'KB_MISSING',
  KBUnexpected: 'KB_UNEXPECTED',
  KBUnsupported: 'KB_UNSUPPORTED',
  KBInvalid: 'KB_INVALID',
  KBAudienceMismatch: 'KB_AUDIENCE_MISMATCH',
  KBNonceMismatch: 'KB_NONCE_MISMATCH',
  KBSDHashMismatch: 'KB_SD_HASH_MISMATCH',
  TypeMetadataNotFound: 'TYPE_METADATA_NOT_FOUND',
  TypeMetadataUnavailable: 'TYPE_METADATA_UNAVAILABLE',
  TypeMetadataInvalid: 'TYPE_METADATA_INVALID',
  TypeMetadataViolated: 'TYPE_METADATA_VIOLATED',
  Revoked: 'REVOKED',
  Suspended: 'SUSPENDED',
  StatusNotAccepted: 'STATUS_NOT_ACCEPTED',
  StatusUnavailable: 'STATUS_UNAVAILABLE',
} as const;

export type CodeValue = (typeof Code)[keyof typeof Code];

export class DigitalCredentialError extends Error {
  readonly code: CodeValue;
  constructor(code: CodeValue, message: string, readonly cause?: unknown) {
    super(message);
    this.name = 'DigitalCredentialError';
    this.code = code;
  }
}

export class PolicyError extends Error {
  constructor(message: string, readonly cause?: unknown) {
    super(message);
    this.name = 'PolicyError';
  }
}

export const TypDCSDJWT = 'dc+sd-jwt';
export const TypKBJWT = 'kb+jwt';

export const neverDisclosable = new Set([
  'iss',
  'nbf',
  'exp',
  'cnf',
  'vct',
  'vct#integrity',
  'aka_vcts',
  'status',
]);
