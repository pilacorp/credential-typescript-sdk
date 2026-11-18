import { JSONCredential } from '../../src/vc/json-credential';
import { JWTCredential } from '../../src/vc/jwt-credential';
import type { CredentialData } from '../../src/vc/types';

describe('VC validity leeway', () => {
  const now = Date.now();
  const jsonCases = [
    ['too early', { validFrom: new Date(now + 5000).toISOString() }, 0, /not valid yet/],
    ['early within leeway', { validFrom: new Date(now + 5000).toISOString() }, 30000, null],
    ['too late', { validUntil: new Date(now - 5000).toISOString() }, 0, /expired/],
    ['late within leeway', { validUntil: new Date(now - 5000).toISOString() }, 30000, null],
  ] as const;

  it.each(jsonCases)('JSON %s', async (_name, dates, clockSkewLeewayMs, error) => {
    const credential = new JSONCredential(dates);
    if (error) {
      await expect(
        credential.executeOptions({ checkExpiration: true, clockSkewLeewayMs }),
      ).rejects.toThrow(error);
    } else {
      await expect(
        credential.executeOptions({ checkExpiration: true, clockSkewLeewayMs }),
      ).resolves.toBeUndefined();
    }
  });

  it('JSON credentials ignore root-level nbf/exp (not JWT envelope claims)', async () => {
    const credential = new JSONCredential({
      nbf: Math.floor((now - 60_000) / 1000),
      exp: Math.floor((now + 60_000) / 1000),
      validFrom: new Date(now - 86_400_000).toISOString(),
      validUntil: new Date(now + 86_400_000).toISOString(),
    });
    await expect(
      credential.executeOptions({ checkExpiration: true }),
    ).resolves.toBeUndefined();
  });

  const jwtCases = [
    ['JWT not-before within leeway', { nbf: Math.floor((now + 5000) / 1000) }, 30000, null],
    ['JWT not-before too early', { nbf: Math.floor((now + 5000) / 1000) }, 0, /JWT is not valid yet/],
    ['JWT expiration within leeway', { exp: Math.floor((now - 5000) / 1000) }, 30000, null],
    ['JWT expiration too late', { exp: Math.floor((now - 5000) / 1000) }, 0, /JWT is expired/],
  ] as const;

  it.each(jwtCases)('%s', async (_name, outerClaims, clockSkewLeewayMs, error) => {
    const vc: CredentialData = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential'],
      issuer: 'did:example:issuer',
      validFrom: new Date(now - 86_400_000).toISOString(),
      validUntil: new Date(now + 86_400_000).toISOString(),
      credentialSubject: { id: 'did:example:subject' },
    };
    const credential = jwtCredentialFromOuterClaims(outerClaims, vc);
    if (error) {
      await expect(
        credential.executeOptions({ checkExpiration: true, clockSkewLeewayMs }),
      ).rejects.toThrow(error);
    } else {
      await expect(
        credential.executeOptions({ checkExpiration: true, clockSkewLeewayMs }),
      ).resolves.toBeUndefined();
    }
  });

  it('rejects expired outer JWT even when embedded VC validUntil is still in the future', async () => {
    const vc: CredentialData = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential'],
      issuer: 'did:example:issuer',
      validFrom: new Date(now - 86_400_000).toISOString(),
      validUntil: new Date(now + 86_400_000).toISOString(),
      credentialSubject: { id: 'did:example:subject' },
    };
    const credential = jwtCredentialFromOuterClaims(
      { exp: Math.floor((now - 5000) / 1000) },
      vc,
    );
    await expect(
      credential.executeOptions({ checkExpiration: true }),
    ).rejects.toThrow(/JWT is expired/);
  });
});

function jwtCredentialFromOuterClaims(
  outerClaims: Record<string, unknown>,
  vc: CredentialData,
): JWTCredential {
  const header = Buffer.from(
    JSON.stringify({ typ: 'JWT', alg: 'ES256K', kid: 'did:example:issuer#key-1' }),
    'utf8',
  ).toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({ iss: 'did:example:issuer', vc, ...outerClaims }),
    'utf8',
  ).toString('base64url');
  return new JWTCredential(`${header}.${payload}`, vc, '');
}
