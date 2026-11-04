/**
 * A5 — `revoked` timestamp: formatted as Go's RFC3339Nano (trailing-zero
 * fractional seconds trimmed) so the DID DocHash is byte-identical, and an
 * unparseable `revoked` is rejected on parse rather than silently dropped
 * (which would treat a revoked key as active).
 */
import { formatRFC3339Nano } from '../../src/common/util/time';
import { parseDIDDocument } from '../../src/common/verification-method';
import { didDocumentJSON } from '../../src/didv2/document';
import type { DIDDocument } from '../../src/common/verification-method';

describe('A5: formatRFC3339Nano matches Go time.Time.MarshalJSON', () => {
  it('drops the fractional part entirely at second precision', () => {
    expect(formatRFC3339Nano(new Date('2024-01-02T03:04:05.000Z'))).toBe('2024-01-02T03:04:05Z');
  });
  it('trims trailing zeros in the fractional part', () => {
    expect(formatRFC3339Nano(new Date('2024-01-02T03:04:05.120Z'))).toBe('2024-01-02T03:04:05.12Z');
  });
  it('keeps a full millisecond fraction', () => {
    expect(formatRFC3339Nano(new Date('2024-01-02T03:04:05.123Z'))).toBe('2024-01-02T03:04:05.123Z');
  });
});

describe('A5: DID document serialization of revoked', () => {
  it('emits a trimmed RFC3339 revoked (no ".000Z") in didDocumentJSON', () => {
    const doc: DIDDocument = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: 'did:example:issuer',
      controller: 'did:example:issuer',
      verificationMethod: [
        {
          id: 'did:example:issuer#key-1',
          type: 'EcdsaSecp256k1VerificationKey2019',
          controller: 'did:example:issuer',
          publicKeyHex: '0x04',
          revoked: new Date('2026-01-01T00:00:00.000Z'),
        },
      ],
      authentication: [],
      assertionMethod: [],
    };
    const vm = (didDocumentJSON(doc).verificationMethod as Record<string, unknown>[])[0];
    expect(vm.revoked).toBe('2026-01-01T00:00:00Z');
  });
});

describe('A5: parseDIDDocument revoked handling', () => {
  const base = {
    '@context': [],
    id: 'did:example:issuer',
    verificationMethod: [
      {
        id: 'did:example:issuer#key-1',
        type: 'EcdsaSecp256k1VerificationKey2019',
        controller: 'did:example:issuer',
        publicKeyHex: '0x04',
      },
    ],
    authentication: ['did:example:issuer#key-1'],
    assertionMethod: ['did:example:issuer#key-1'],
  };

  it('parses a valid RFC3339 revoked into a Date', () => {
    const raw = JSON.parse(JSON.stringify(base));
    raw.verificationMethod[0].revoked = '2026-01-01T00:00:00Z';
    const doc = parseDIDDocument(raw);
    expect(doc.verificationMethod[0].revoked).toBeInstanceOf(Date);
  });

  it('rejects an unparseable revoked instead of silently dropping it', () => {
    const raw = JSON.parse(JSON.stringify(base));
    raw.verificationMethod[0].revoked = 'not-a-timestamp';
    expect(() => parseDIDDocument(raw)).toThrow(/unparseable 'revoked'/);
  });
});
