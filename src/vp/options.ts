import { newHTTPResolver, ResolverProvider } from '../common/verification-method';
import { vpConfig } from './config';
import type { PresentationOptions } from './types';

export interface ResolvedPresentationOptions {
  validateVC: boolean;
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
    validateVC: opts.validateVC ?? false,
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
