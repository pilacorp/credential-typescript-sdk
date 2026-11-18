/**
 * EnvelopedVerifiableCredential unwrap — port of the vc-jose-cose §4.13 path in
 * vc/credential.go ParseCredential. A JSON object with a
 * `data:application/vc+jwt,` id and type EnvelopedVerifiableCredential is read
 * as the enveloped token; the id prefix without the type is refused.
 */
import { secp256k1 } from '@noble/curves/secp256k1';
import { bytesToHex, hexToBytes } from '../../src/common/crypto/hex';
import { DefaultProvider } from '../../src/common/signer/default-provider';
import { DIDDocument, ResolverProvider } from '../../src/common/verification-method';
import { JOSECredential } from '../../src/vc/jose-credential';
import { parseCredential } from '../../src/vc/credential';

const ISSUER = 'did:example:issuer';
const SUBJECT = 'did:example:subject';
const ISSUER_PRIV = '4646464646464646464646464646464646464646464646464646464646464646';
const V2 = 'https://www.w3.org/ns/credentials/v2';

class StaticResolver implements ResolverProvider {
  constructor(private readonly doc: DIDDocument) {}
  async resolveDocument(): Promise<DIDDocument> {
    return this.doc;
  }
}

function secpDid(): DIDDocument {
  const pubHex = bytesToHex(secp256k1.getPublicKey(hexToBytes(ISSUER_PRIV), false));
  return {
    '@context': [],
    id: ISSUER,
    verificationMethod: [
      { id: `${ISSUER}#key-1`, type: 'EcdsaSecp256k1VerificationKey2019', controller: ISSUER, publicKeyHex: pubHex },
    ],
    authentication: [`${ISSUER}#key-1`],
    assertionMethod: [`${ISSUER}#key-1`],
  };
}

async function envelopedJSON(resolver: ResolverProvider): Promise<string> {
  const cred = await JOSECredential.create(
    { context: [V2], types: ['VerifiableCredential'], issuer: ISSUER, subject: [{ id: SUBJECT }] },
    { verificationMethodKey: 'key-1', resolver },
  );
  await cred.addProofByProvider(new DefaultProvider(ISSUER_PRIV), { resolver });
  const token = await cred.serialize();
  return JSON.stringify({
    '@context': [V2],
    type: ['EnvelopedVerifiableCredential'],
    id: `data:application/vc+jwt,${token}`,
  });
}

describe('EnvelopedVerifiableCredential unwrap', () => {
  const resolver = new StaticResolver(secpDid());

  it('unwraps and verifies an enveloped vc+jwt', async () => {
    const json = await envelopedJSON(resolver);
    const cred = await parseCredential(json, { resolver });
    expect(cred.getType()).toBe('JOSE');
    await expect(cred.verify({ resolver })).resolves.toBeUndefined();
  });

  it('refuses the data: id when the type is not EnvelopedVerifiableCredential', async () => {
    const json = await envelopedJSON(resolver);
    const broken = JSON.stringify({ ...JSON.parse(json), type: ['VerifiableCredential'] });
    await expect(parseCredential(broken, { resolver })).rejects.toThrow(/EnvelopedVerifiableCredential/);
  });
});
