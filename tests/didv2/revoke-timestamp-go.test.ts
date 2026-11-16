/**
 * E28: revoke/rotate take an RFC3339(Nano) string and keep its offset and
 * nanoseconds, so `revoked` and DocHash match Go's time.Time. The expected hash
 * is Go didv2/did.DIDDocument.Hash after RevokeVerificationMethod with
 * time.Parse(RFC3339Nano, REVOKED) on the same document.
 */
import { parseDIDDocument } from '../../src/common/verification-method/verification-method';
import { didDocumentJSON } from '../../src/didv2/document';
import { docHash } from '../../src/didv2/subdid';
import { revokeVerificationMethod, rotateVerificationMethod } from '../../src/didv2/vm-ops';

const DID = 'did:nda:0x1111111111111111111111111111111111111111';
const REVOKED = '2026-11-13T15:04:05.123456789+07:00';
const GO_DOC_HASH = '0x8256adbf858bf544046f1869f9c8627334ce948f852b1a102f975aa81b17b642';

const raw = () => ({
  '@context': ['https://www.w3.org/ns/did/v1'],
  id: DID,
  controller: DID,
  verificationMethod: [{
    id: `${DID}#key-1`, type: 'EcdsaSecp256k1VerificationKey2019', controller: DID,
    publicKeyHex: '0x02bbe4f0cd3c1d8b8ac5a3f39e6bda5c6c1e9c3a69f6db3c4d6c2bfe14b4fa9b4b',
  }],
  authentication: [`${DID}#key-1`],
  assertionMethod: [`${DID}#key-1`],
  didDocumentMetadata: { type: 'people' },
});

describe('DID v2 revoke/rotate timestamps (E28)', () => {
  it('keeps offset and nanoseconds of an RFC3339Nano string; DocHash equals Go', () => {
    const doc = parseDIDDocument(raw());
    revokeVerificationMethod(doc, '#key-1', 'keyCompromise', REVOKED);
    const vm = (didDocumentJSON(doc).verificationMethod as Record<string, unknown>[])[0];
    expect(vm.revoked).toBe(REVOKED);
    expect(docHash(doc)).toBe(GO_DOC_HASH);
  });

  it('rotate accepts the same string form', () => {
    const doc = parseDIDDocument(raw());
    rotateVerificationMethod(doc, '#key-1', {
      publicKeyHex: '0x03354b9ae48c3cecaf6636ba88e321847edbf450a2777a012240d6d51705de73d7',
    }, 'superseded', REVOKED);
    expect((didDocumentJSON(doc).verificationMethod as Record<string, unknown>[])[0].revoked).toBe(REVOKED);
  });

  it('still accepts a Date, and refuses a non-RFC3339 string', () => {
    const doc = parseDIDDocument(raw());
    revokeVerificationMethod(doc, '#key-1', 'keyCompromise', new Date('2026-11-13T08:04:05.123Z'));
    expect((didDocumentJSON(doc).verificationMethod as Record<string, unknown>[])[0].revoked).toBe('2026-11-13T08:04:05.123Z');
    expect(() => revokeVerificationMethod(parseDIDDocument(raw()), '#key-1', 'x', '2026-11-13')).toThrow(/RFC3339/);
  });
});
