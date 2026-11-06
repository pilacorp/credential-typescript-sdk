/**
 * A4 — DID document hashing byte-identical to Go for the awkward metadata
 * cases: non-ASCII text, a native integer, a timestamp (time.Time), and a
 * nested object. The expected DocHash was produced by the Go SDK
 * (didv2/did.DIDDocument.Hash) for the exact same inputs.
 */
import { DIDTypePeople } from '../../src/didv2';
import { generateDIDDocument } from '../../src/didv2/document';
import { docHash } from '../../src/didv2/subdid';

const ROOT = 'did:nda:0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a';
const SUB = 'did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071';
const PUB = '0x03354b9ae48c3cecaf6636ba88e321847edbf450a2777a012240d6d51705de73d7';

// Go didv2/did.DIDDocument.Hash of the document below.
const GO_DOC_HASH = '0x2f143b6e37e408ac4d4c829ba85469a6233ba25c4ad6b0dd5584c89fef188107';

describe('A4: DID DocHash matches Go for non-ASCII / numeric / Date metadata', () => {
  it('hashes identically to the Go SDK', () => {
    const doc = generateDIDDocument(PUB, SUB, '', ROOT, DIDTypePeople, {
      label: 'Nguyễn Văn A 日本語 €',
      count: 7,
      revokedAt: new Date('2026-01-02T03:04:05Z'),
      nested: { b: 'β', a: 1 },
    })!;
    expect(docHash(doc)).toBe(GO_DOC_HASH);
  });
});
