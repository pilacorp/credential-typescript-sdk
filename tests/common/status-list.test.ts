import { compressToBase64URL } from '../../src/common/util/compress';
import {
  bitAt,
  isRevoked,
  isStatusSet,
  StatusListClient,
} from '../../src/common/credential-status';

describe('StatusList client', () => {
  it('checks a bit position independently of purpose wrapping', () => {
    const bits = new Uint8Array(16);
    bits[0] = 0b00000010;
    const encoded = compressToBase64URL(bits);
    expect(bitAt(1, encoded)).toBe(true);
    expect(bitAt(0, encoded)).toBe(false);
    expect(isRevoked(1, { encodedList: encoded, id: 'x', statusPurpose: 'revocation', type: 'BitstringStatusList' })).toBe(true);
    expect(isStatusSet(1, { encodedList: encoded, id: 'x', statusPurpose: 'suspension', type: 'BitstringStatusList' }, 'suspension')).toBe(true);
    expect(isRevoked(1, { encodedList: encoded, id: 'x', statusPurpose: 'suspension', type: 'BitstringStatusList' })).toBe(false);
  });

  it('injects transport via fetchFn', async () => {
    const bits = new Uint8Array(16);
    const encoded = compressToBase64URL(bits);
    const fetchFn = jest.fn(async () =>
      new Response(
        JSON.stringify({
          data: {
            credentialSubject: {
              encodedList: encoded,
              id: 'list',
              statusPurpose: 'revocation',
              type: 'BitstringStatusList',
            },
          },
        }),
        { status: 200 },
      ),
    ) as unknown as typeof fetch;
    const client = new StatusListClient({ fetchFn });
    const resp = await client.fetchStatusListCredential('https://example.test/status');
    expect(resp.data.credentialSubject.encodedList).toBe(encoded);
    expect(fetchFn).toHaveBeenCalled();
  });
});
