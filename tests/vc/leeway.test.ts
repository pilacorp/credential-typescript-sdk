import { JSONCredential } from '../../src/vc/json-credential';

describe('VC validity leeway', () => {
  const now = Date.now();
  const cases = [
    ['too early', { validFrom: new Date(now + 5000).toISOString() }, 0, /not valid yet/],
    ['early within leeway', { validFrom: new Date(now + 5000).toISOString() }, 30000, null],
    ['too late', { validUntil: new Date(now - 5000).toISOString() }, 0, /expired/],
    ['late within leeway', { validUntil: new Date(now - 5000).toISOString() }, 30000, null],
    ['JWT not-before within leeway', { nbf: Math.floor((now + 5000) / 1000) }, 30000, null],
    ['JWT not-before too early', { nbf: Math.floor((now + 5000) / 1000) }, 0, /JWT is not valid yet/],
    ['JWT expiration within leeway', { exp: Math.floor((now - 5000) / 1000) }, 30000, null],
    ['JWT expiration too late', { exp: Math.floor((now - 5000) / 1000) }, 0, /JWT is expired/],
  ] as const;

  it.each(cases)('%s', async (_name, dates, clockSkewLeewayMs, error) => {
    const credential = new JSONCredential(dates);
    if (error) {
      await expect(credential.executeOptions({ checkExpiration: true, clockSkewLeewayMs })).rejects.toThrow(error);
    } else {
      await expect(credential.executeOptions({ checkExpiration: true, clockSkewLeewayMs })).resolves.toBeUndefined();
    }
  });
});
