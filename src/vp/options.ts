import { newHTTPResolver, ResolverProvider } from '../common/verification-method';
import { vpConfig } from './config';
import type { CredentialOptions } from '../vc/types';
import type { PresentationOptions } from './types';

export interface ResolvedPresentationOptions {
  validateVC: boolean;
  /** Extra options forwarded to each embedded credential's verify(). */
  vcOpts: CredentialOptions;
  proofVerificationMethod: string;
  replaceProof: boolean;
  verifyProof: boolean;
  checkExpiration: boolean;
  clockSkewLeewayMs: number;
  didBaseURL: string;
  verificationMethodKey: string;
  resolver: ResolverProvider;
  challenge: string;
  domain: string;
  expectedChallenge: string;
  expectedDomain: string;
  requireAudience: boolean;
}

export function getOptions(opts: PresentationOptions = {}): ResolvedPresentationOptions {
  const didBaseURL = opts.didBaseURL ?? vpConfig.baseURL;
  const expectedChallenge = opts.expectedChallenge ?? '';
  const expectedDomain = opts.expectedDomain ?? '';
  const requireAudience = opts.requireAudience ?? false;
  const verifyImplied = Boolean(expectedChallenge || expectedDomain || requireAudience);
  return {
    validateVC: Boolean(opts.validateVC),
    vcOpts: typeof opts.validateVC === 'object' && opts.validateVC ? opts.validateVC : {},
    proofVerificationMethod: opts.proofVerificationMethod ?? '',
    replaceProof: opts.replaceProof ?? false,
    verifyProof: opts.verifyProof || verifyImplied,
    checkExpiration: opts.checkExpiration ?? false,
    clockSkewLeewayMs: Math.max(opts.clockSkewLeewayMs ?? 0, 0),
    didBaseURL,
    verificationMethodKey: opts.verificationMethodKey ?? '',
    resolver: opts.resolver ?? newHTTPResolver(didBaseURL),
    challenge: opts.challenge ?? '',
    domain: opts.domain ?? '',
    expectedChallenge,
    expectedDomain,
    requireAudience,
  };
}

/** Options for a signing call: nothing to verify yet, so verification-implying options are dropped. */
export function signingOptions(opts: PresentationOptions): PresentationOptions {
  return {
    ...opts,
    verifyProof: false,
    expectedChallenge: undefined,
    expectedDomain: undefined,
    requireAudience: false,
  };
}

export function refuseOverwrite(current: string, opts: PresentationOptions): void {
  if (!current || opts.replaceProof) return;
  throw new Error(
    'presentation is already signed; signing again would replace that signature; pass replaceProof to do so deliberately',
  );
}

export function refuseReplaceOnJSONLD(opts: PresentationOptions): void {
  if (!opts.replaceProof) return;
  throw new Error(
    'replaceProof does not apply to JSON-LD: proofs are appended to the proof set, not replaced; build a new presentation without the proof to re-sign',
  );
}

/** A JWT signing call must not silently drop options only the constructor applies. */
export function rejectBuildTimeOptions(opts: PresentationOptions, signedOutside: boolean): void {
  if (opts.verificationMethodKey) {
    throw new Error(
      "verificationMethodKey cannot be applied when signing a JWT: the header's kid was fixed when the token was built; pass the option to the constructor",
    );
  }
  if (signedOutside && (opts.challenge || opts.domain)) {
    throw new Error(
      'challenge / domain cannot be applied by addCustomProof: the signature already covers the signing input; pass them to the constructor before getSigningInput, or sign with addProofByProvider',
    );
  }
}
