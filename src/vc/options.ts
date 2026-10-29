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
  };
}
