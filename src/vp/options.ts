import { newHTTPResolver, ResolverProvider } from '../common/verification-method';
import { vpConfig } from './config';
import type { PresentationOptions } from './types';

export interface ResolvedPresentationOptions {
  validateVC: boolean;
  verifyProof: boolean;
  checkExpiration: boolean;
  didBaseURL: string;
  verificationMethodKey: string;
  resolver: ResolverProvider;
}

export function getOptions(opts: PresentationOptions = {}): ResolvedPresentationOptions {
  const didBaseURL = opts.didBaseURL ?? vpConfig.baseURL;
  return {
    validateVC: opts.validateVC ?? false,
    verifyProof: opts.verifyProof ?? false,
    checkExpiration: opts.checkExpiration ?? false,
    didBaseURL,
    verificationMethodKey: opts.verificationMethodKey ?? '',
    resolver: opts.resolver ?? newHTTPResolver(didBaseURL),
  };
}
