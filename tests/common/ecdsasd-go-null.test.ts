import { verifyProof } from '../../src/common/ecdsasd/api';
import fixture from '../fixtures/ecdsasd/go-derived-mandatory-only.json';

// Go encodes an empty signature list in a derived proof as CBOR null (0xf6).
describe('ecdsa-sd-2023 derived proof from Go revealing only mandatory statements', () => {
  it('verifies', async () => {
    await expect(
      verifyProof(fixture.reveal, fixture.proofConfig, fixture.proofValue, Buffer.from(fixture.pub, 'hex')),
    ).resolves.toBeUndefined();
  });

  it('still rejects a tampered revealed document', async () => {
    const reveal = { ...fixture.reveal, issuer: 'did:example:other' };
    await expect(
      verifyProof(reveal, fixture.proofConfig, fixture.proofValue, Buffer.from(fixture.pub, 'hex')),
    ).rejects.toThrow();
  });
});
