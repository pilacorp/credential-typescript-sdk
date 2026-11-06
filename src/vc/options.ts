import { newHTTPResolver, ResolverProvider } from '../common/verification-method';
import { vcConfig } from './config';
import type { CredentialOptions } from './types';

export interface ResolvedCredentialOptions extends Required<
  Pick<
    CredentialOptions,
    | 'validateSchema'
    | 'verifyProof'
    | 'checkExpiration'
    | 'checkRevocation'
    | 'clockSkewLeewayMs'
    | 'verificationMethodKey'
    | 'sdShuffle'
  >
> {
  didBaseURL: string;
  sdDisclosures: string[];
  sdSelectivePaths: string[];
  sdAlg: string;
  sdDecoys: NonNullable<CredentialOptions['sdDecoys']>;
  schemaLoader: CredentialOptions['schemaLoader'];
  resolver: ResolverProvider;
  proofVerificationMethod: string;
  replaceProof: boolean;
}

/** True when any SD-JWT option is set (go credentialOptions.hasSDOptions). */
export function hasSDOptions(o: CredentialOptions): boolean {
  return (
    (o.sdDisclosures?.length ?? 0) > 0 ||
    (o.sdSelectivePaths?.length ?? 0) > 0 ||
    Boolean(o.sdAlg) ||
    Boolean(o.sdShuffle) ||
    (o.sdDecoys?.length ?? 0) > 0
  );
}

/** Options for a signing call: there is no signature to verify yet (go signingOptions). */
export function signingOptions(opts: CredentialOptions): CredentialOptions {
  return { ...opts, verifyProof: false };
}

/** A JWT signing call must not silently drop options only the constructors apply. */
export function rejectBuildTimeOptions(opts: CredentialOptions): void {
  if (opts.verificationMethodKey) {
    throw new Error(
      "verificationMethodKey cannot be applied when signing a JWT: the header's kid was fixed when the token was built; pass the option to the constructor",
    );
  }
  if (hasSDOptions(opts)) {
    throw new Error(
      'SD-JWT options cannot be applied when signing: the disclosures were fixed when the token was built; pass them to JOSECredential.create',
    );
  }
}

/** Signing something already signed is refused unless replaceProof is set. */
export function refuseOverwrite(current: string, opts: CredentialOptions): void {
  if (!current || opts.replaceProof) return;
  throw new Error(
    'credential is already signed; signing again would replace that signature; pass replaceProof to do so deliberately',
  );
}

/** JSON-LD signing appends to the proof set, so replaceProof is refused, not ignored. */
export function refuseReplaceOnJSONLD(opts: CredentialOptions): void {
  if (!opts.replaceProof) return;
  throw new Error(
    'replaceProof does not apply to JSON-LD: proofs are appended to the proof set, not replaced; build a new credential without the proof to re-sign',
  );
}

export function getOptions(opts: CredentialOptions = {}): ResolvedCredentialOptions {
  const didBaseURL = opts.didBaseURL ?? vcConfig.baseURL;
  return {
    validateSchema: opts.validateSchema ?? false,
    verifyProof: opts.verifyProof ?? false,
    checkExpiration: opts.checkExpiration ?? false,
    checkRevocation: opts.checkRevocation ?? false,
    clockSkewLeewayMs: Math.max(opts.clockSkewLeewayMs ?? 0, 0),
    didBaseURL,
    verificationMethodKey: opts.verificationMethodKey ?? '',
    sdDisclosures: opts.sdDisclosures ?? [],
    sdSelectivePaths: opts.sdSelectivePaths ?? [],
    sdAlg: opts.sdAlg ?? '',
    sdShuffle: opts.sdShuffle ?? false,
    sdDecoys: opts.sdDecoys ?? [],
    schemaLoader: opts.schemaLoader,
    resolver: opts.resolver ?? newHTTPResolver(didBaseURL),
    proofVerificationMethod: opts.proofVerificationMethod ?? '',
    replaceProof: opts.replaceProof ?? false,
  };
}
