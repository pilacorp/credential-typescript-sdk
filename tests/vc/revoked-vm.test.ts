import { secp256k1 } from '@noble/curves/secp256k1';
import { p256 } from '@noble/curves/nist';
import { bytesToHex, hexToBytes } from '../../src/common/crypto/hex';
import { DefaultProvider } from '../../src/common/signer/default-provider';
import { P256Provider } from '../../src/common/signer/p256-provider';
import { encodeP256PublicMultibase } from '../../src/common/verification-method/multikey';
import type { DIDDocument, ResolverProvider } from '../../src/common/verification-method';
import { JSONCredential } from '../../src/vc/json-credential';
import { JOSECredential } from '../../src/vc/jose-credential';
import { ECDSASDCredential } from '../../src/vc/ecdsasd-credential';

const ISSUER = 'did:example:vc-rotated';
const SUBJECT = 'did:example:subject';
const SECP_PRIV = '4646464646464646464646464646464646464646464646464646464646464646';
const P256_PRIV = '1111111111111111111111111111111111111111111111111111111111111111';

class StaticResolver implements ResolverProvider {
  constructor(private readonly doc: DIDDocument) {}
  async resolveDocument(): Promise<DIDDocument> {
    return this.doc;
  }
}

function secpDoc(): DIDDocument {
  const pubHex = bytesToHex(secp256k1.getPublicKey(hexToBytes(SECP_PRIV), false));
  const revoked = new Date(Date.now() - 3600_000);
  return {
    '@context': [],
    id: ISSUER,
    verificationMethod: [
      {
        id: `${ISSUER}#key-1`,
        type: 'EcdsaSecp256k1VerificationKey2019',
        controller: ISSUER,
        publicKeyHex: pubHex,
        revoked,
      },
      {
        id: `${ISSUER}#key-2`,
        type: 'EcdsaSecp256k1VerificationKey2019',
        controller: ISSUER,
        publicKeyHex: pubHex,
      },
    ],
    authentication: [`${ISSUER}#key-1`, `${ISSUER}#key-2`],
    assertionMethod: [`${ISSUER}#key-1`, `${ISSUER}#key-2`],
  };
}

function p256Doc(): DIDDocument {
  const pub = p256.getPublicKey(hexToBytes(P256_PRIV), false);
  const mb = encodeP256PublicMultibase(pub);
  const revoked = new Date(Date.now() - 3600_000);
  return {
    '@context': [],
    id: ISSUER,
    verificationMethod: [
      {
        id: `${ISSUER}#key-1`,
        type: 'Multikey',
        controller: ISSUER,
        publicKeyMultibase: mb,
        revoked,
      },
      {
        id: `${ISSUER}#key-2`,
        type: 'Multikey',
        controller: ISSUER,
        publicKeyMultibase: mb,
      },
    ],
    authentication: [`${ISSUER}#key-1`, `${ISSUER}#key-2`],
    assertionMethod: [`${ISSUER}#key-1`, `${ISSUER}#key-2`],
  };
}

const contents = {
  context: ['https://www.w3.org/ns/credentials/v2'],
  types: ['VerifiableCredential'],
  issuer: ISSUER,
  subject: [{ id: SUBJECT, customFields: { name: 'Alice' } }],
};

describe('revoked VM rejected at signing', () => {
  it('JSONCredential: default skips key-1; pinned key-1 is rejected; key-2 signs', async () => {
    const resolver = new StaticResolver(secpDoc());
    const signer = new DefaultProvider(SECP_PRIV);

    const auto = await JSONCredential.create(contents, { resolver });
    await auto.addProofByProvider(signer, { resolver });
    await auto.verify({ resolver, verifyProof: true });

    const pinnedRevoked = await JSONCredential.create(contents, { resolver });
    await expect(
      pinnedRevoked.addProofByProvider(signer, { resolver, verificationMethodKey: 'key-1' }),
    ).rejects.toThrow(/was revoked at/);

    const pinnedActive = await JSONCredential.create(contents, { resolver });
    await pinnedActive.addProofByProvider(signer, { resolver, verificationMethodKey: 'key-2' });
    await pinnedActive.verify({ resolver, verifyProof: true });
  });

  it('JOSECredential: pinned revoked key-1 is rejected at create and addProof', async () => {
    const resolver = new StaticResolver(secpDoc());
    await expect(
      JOSECredential.create(contents, { resolver, verificationMethodKey: 'key-1' }),
    ).rejects.toThrow(/was revoked at/);

    const cred = await JOSECredential.create(contents, { resolver, verificationMethodKey: 'key-2' });
    await expect(
      cred.addProofByProvider(new DefaultProvider(SECP_PRIV), {
        resolver,
        verificationMethodKey: 'key-1',
      }),
    ).rejects.toThrow(/was revoked at/);

    await cred.addProofByProvider(new DefaultProvider(SECP_PRIV), { resolver });
    await cred.verify({ resolver, verifyProof: true });
  });

  it('ECDSASDCredential: pinned revoked key-1 is rejected', async () => {
    const resolver = new StaticResolver(p256Doc());
    const cred = await ECDSASDCredential.create(contents, { resolver });
    await expect(
      cred.addProofByProvider(new P256Provider(P256_PRIV), ['/issuer'], {
        resolver,
        verificationMethodKey: 'key-1',
      }),
    ).rejects.toThrow(/was revoked at/);

    await cred.addProofByProvider(new P256Provider(P256_PRIV), ['/issuer'], {
      resolver,
      verificationMethodKey: 'key-2',
    });
    await cred.verify({ resolver, verifyProof: true });
  });
});
