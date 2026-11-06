import { JOSECredential } from '../../src/vc/jose-credential';
import { DefaultProvider } from '../../src/common/signer/default-provider';
import {
  DIDDocument,
  ResolverProvider,
  StaticResolver
} from '../../src/common/verification-method';
import { bytesToHex, hexToBytes } from '../../src/common/crypto/hex';
import { secp256k1 } from '@noble/curves/secp256k1';
import { ErrorCode } from '../../src/common/errors';

const ISSUER = 'did:example:issuer';
const SUBJECT = 'did:example:subject';
const SECP_PRIV = '4646464646464646464646464646464646464646464646464646464646464646';

function secpDid(): DIDDocument {
  const pubHex = bytesToHex(secp256k1.getPublicKey(hexToBytes(SECP_PRIV), false));
  return {
    '@context': [],
    id: ISSUER,
    verificationMethod: [
      {
        id: `${ISSUER}#key-1`,
        type: 'EcdsaSecp256k1VerificationKey2019',
        controller: ISSUER,
        publicKeyHex: pubHex,
      },
    ],
    authentication: [`${ISSUER}#key-1`],
    assertionMethod: [`${ISSUER}#key-1`],
  };
}

describe('JOSECredential Present/Hash/DecodedDisclosures', () => {
  it('presents a subset of SD-JWT disclosures and hashes the token', async () => {
    const resolver = new StaticResolver(secpDid());
    const cred = await JOSECredential.create(
      {
        context: ['https://www.w3.org/ns/credentials/v2'],
        types: ['VerifiableCredential'],
        issuer: ISSUER,
        subject: [{ id: SUBJECT, customFields: { name: 'Alice', salary: 'hidden' } }],
      },
      {
        verificationMethodKey: 'key-1',
        resolver,
        sdSelectivePaths: ['credentialSubject.name', 'credentialSubject.salary'],
      },
    );
    await cred.addProofByProvider(new DefaultProvider(SECP_PRIV), { resolver });

    const decoded = cred.decodedDisclosures();
    expect(decoded.length).toBeGreaterThanOrEqual(2);
    const nameDisc = decoded.find((d) => d.fieldName === 'name');
    expect(nameDisc).toBeDefined();

    const presented = await cred.present([nameDisc!.disclosure]);
    expect(presented.decodedDisclosures()).toHaveLength(1);
    expect(presented.decodedDisclosures()[0].fieldName).toBe('name');

    const digest = await presented.hash();
    expect(digest).toMatch(/^[0-9a-f]{64}$/);

    const token = await presented.serialize();
    expect(token.endsWith('~')).toBe(true);
    await JOSECredential.parse(token, { resolver, verifyProof: true });
  });

  it('refuses Present on a non-SD vc+jwt', async () => {
    const resolver = new StaticResolver(secpDid());
    const cred = await JOSECredential.create(
      {
        context: ['https://www.w3.org/ns/credentials/v2'],
        types: ['VerifiableCredential'],
        issuer: ISSUER,
        subject: [{ id: SUBJECT }],
      },
      { verificationMethodKey: 'key-1', resolver },
    );
    await cred.addProofByProvider(new DefaultProvider(SECP_PRIV), { resolver });
    await expect(cred.present([])).rejects.toMatchObject({ code: ErrorCode.NoDisclosures });
  });
});
