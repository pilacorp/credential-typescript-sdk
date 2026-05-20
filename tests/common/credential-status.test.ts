import { compressToBase64URL } from '../../src/common/util/compress';
import { isRevoked } from '../../src/common/credential-status/credential-status';

describe('isRevoked', () => {
  it('flags bit 0 as revoked when encodedList=0x01', () => {
    const encodedList = compressToBase64URL(new Uint8Array([0x01]));
    expect(isRevoked(0, { encodedList, id: '', statusPurpose: 'revocation', type: 'BitstringStatusList' })).toBe(true);
    expect(isRevoked(1, { encodedList, id: '', statusPurpose: 'revocation', type: 'BitstringStatusList' })).toBe(false);
  });

  it('non-revocation purpose always returns false', () => {
    const encodedList = compressToBase64URL(new Uint8Array([0x01]));
    expect(isRevoked(0, { encodedList, id: '', statusPurpose: 'suspension', type: '' })).toBe(false);
  });

  it('throws on out-of-bounds position', () => {
    const encodedList = compressToBase64URL(new Uint8Array([0x00]));
    expect(() =>
      isRevoked(100, { encodedList, id: '', statusPurpose: 'revocation', type: '' }),
    ).toThrow(/out of range/);
  });
});
