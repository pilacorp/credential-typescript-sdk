import { CredentialError, ErrorCode } from '../common/errors';
import type { ResolvedPresentationOptions } from './options';

export function audContains(aud: unknown, domain: string): boolean {
  if (typeof aud === 'string') return aud === domain;
  if (Array.isArray(aud)) {
    return aud.some((item) => typeof item === 'string' && item === domain);
  }
  return false;
}

export function checkAudience(aud: unknown, options: ResolvedPresentationOptions): void {
  if (options.expectedDomain) {
    if (!audContains(aud, options.expectedDomain)) {
      throw new CredentialError(
        ErrorCode.DomainMismatch,
        `aud ${JSON.stringify(aud)} does not match expected domain ${JSON.stringify(options.expectedDomain)}`,
      );
    }
    return;
  }
  if (options.requireAudience) {
    throw new CredentialError(
      ErrorCode.AudienceUnbound,
      'WithRequireAudience needs WithExpectedDomain',
    );
  }
}

export function checkChallenge(actual: unknown, expected: string): void {
  if (!expected) return;
  if (actual !== expected) {
    throw new CredentialError(
      ErrorCode.ChallengeMismatch,
      `nonce ${JSON.stringify(actual)} does not match expected challenge ${JSON.stringify(expected)}`,
    );
  }
}
