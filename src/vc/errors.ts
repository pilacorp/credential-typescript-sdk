import { CredentialError, ErrorCode } from '../common/errors';

/** go vc.ErrSDJWTRequiresJOSE: selective disclosure is only issued/read as vc+sd-jwt. */
export const ErrSDJWTRequiresJOSEMessage =
  'selective disclosure is supported only as vc+sd-jwt; use JOSECredential.create / JOSECredential.parse';

export function sdJWTRequiresJOSE(context: string): CredentialError {
  return new CredentialError(ErrorCode.SDJWTRequiresJOSE, `${context}: ${ErrSDJWTRequiresJOSEMessage}`);
}

/** errors.Is(err, ErrSDJWTRequiresJOSE) */
export function isSDJWTRequiresJOSE(err: unknown): boolean {
  return err instanceof CredentialError && err.code === ErrorCode.SDJWTRequiresJOSE;
}
