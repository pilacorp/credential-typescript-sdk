import { JSONPresentation } from '../../src/vp/json-presentation';

describe('VP validity leeway', () => {
  const now = Date.now();
  const cases = [
    ['too early', { validFrom: new Date(now + 5000).toISOString() }, 0, /not valid yet/],
    ['early within leeway', { validFrom: new Date(now + 5000).toISOString() }, 30000, null],
    ['too late', { validUntil: new Date(now - 5000).toISOString() }, 0, /expired/],
    ['late within leeway', { validUntil: new Date(now - 5000).toISOString() }, 30000, null],
  ] as const;

  it.each(cases)('%s', async (_name, dates, clockSkewLeewayMs, error) => {
    const presentation = new JSONPresentation(dates);
    if (error) {
      await expect(presentation.executeOptions({ checkExpiration: true, clockSkewLeewayMs })).rejects.toThrow(error);
    } else {
      await expect(presentation.executeOptions({ checkExpiration: true, clockSkewLeewayMs })).resolves.toBeUndefined();
    }
  });
});
