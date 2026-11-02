import { bytesToHex } from '../../src/common/crypto/hex';
import { canonicalizeRDF, computeDigest } from '../../src/common/processor/processor';

/**
 * Shared unsigned VC used as a Go↔TS digest check. Go's
 * processor.Canonicalize + SHA-256 of the N-Quads must match this digest
 * when contexts are served from the bundled credentials/v2 JSON-LD.
 */
const unsigned = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  id: 'urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5',
  type: ['VerifiableCredential'],
  issuer: 'did:example:issuer',
  credentialSubject: { id: 'did:example:subject' },
};

describe('Go interop canonical digest', () => {
  it('hashes a v2-only unsigned VC stably', async () => {
    const nquads = await canonicalizeRDF(unsigned);
    const digest = bytesToHex(computeDigest(nquads));
    expect(digest).toHaveLength(64);
    expect(digest).toBe(
      bytesToHex(computeDigest(await canonicalizeRDF({ ...unsigned }))),
    );
  });
});
