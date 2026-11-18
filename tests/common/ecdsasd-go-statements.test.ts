import { p256 } from '@noble/curves/nist';
import { createBaseProof, deriveProof, verifyProof } from '../../src/common/ecdsasd/api';
import { P256Provider } from '../../src/common/signer/p256-provider';
import goEmoji from '../fixtures/ecdsasd/go-emoji-fullwidth.json';

const PRIV = 'c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721';
const pub = p256.getPublicKey(Buffer.from(PRIV, 'hex'), false);
const copy = <T>(v: T): T => JSON.parse(JSON.stringify(v));

const proofConfig = {
  '@context': ['https://www.w3.org/ns/credentials/v2', 'https://www.w3.org/ns/credentials/examples/v2'],
  type: 'DataIntegrityProof',
  cryptosuite: 'ecdsa-sd-2023',
  created: '2026-01-01T00:00:00Z',
  verificationMethod: 'did:example:issuer#key-2',
  proofPurpose: 'assertionMethod',
};

const credential = (subjectId: string) => ({
  '@context': ['https://www.w3.org/ns/credentials/v2', 'https://www.w3.org/ns/credentials/examples/v2'],
  id: 'urn:uuid:t1',
  type: ['VerifiableCredential', 'ExampleCredential'],
  issuer: 'did:example:issuer',
  credentialSubject: { id: subjectId, name: 'A' },
});

describe('ecdsa-sd-2023 statements with characters Go escapes or sorts differently', () => {
  // A quad whose IRI holds `"` or `\` must still be grouped as mandatory.
  for (const id of ['urn:a"b', 'urn:a\\b']) {
    it(`keeps a subject with id ${JSON.stringify(id)} mandatory`, async () => {
      const doc = credential(id);
      const base = await createBaseProof(copy(doc), copy(proofConfig), ['/issuer', '/credentialSubject'], new P256Provider(PRIV), pub);
      const { revealDoc, proofValue } = await deriveProof(copy(doc), base, []);
      await expect(verifyProof(copy(revealDoc), copy(proofConfig), proofValue, pub)).resolves.toBeUndefined();

      const stripped = copy(revealDoc) as Record<string, unknown>;
      delete stripped.credentialSubject;
      await expect(verifyProof(stripped, copy(proofConfig), proofValue, pub)).rejects.toThrow();
    });
  }

  // Go orders statements by bytes; UTF-16 order differs for U+1F600 next to U+FF46.
  it('verifies a Go-made base and derived proof over "😀" and "ｆ"', async () => {
    const goPub = Buffer.from(goEmoji.pub, 'hex');
    await expect(verifyProof(copy(goEmoji.document), copy(goEmoji.proofConfig), goEmoji.baseProof, goPub)).resolves.toBeUndefined();
    await expect(verifyProof(copy(goEmoji.reveal), copy(goEmoji.proofConfig), goEmoji.proofValue, goPub)).resolves.toBeUndefined();
  });
});
