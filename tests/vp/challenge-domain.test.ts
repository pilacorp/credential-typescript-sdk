import { secp256k1 } from '@noble/curves/secp256k1';
import { bytesToHex, hexToBytes } from '../../src/common/crypto/hex';
import { DIDDocument, ResolverProvider } from '../../src/common/verification-method';
import { JWTPresentation } from '../../src/vp/jwt-presentation';
import { JSONPresentation } from '../../src/vp/json-presentation';
import { ErrorCode } from '../../src/common/errors';
import { DefaultProvider } from '../../src/common/signer/default-provider';

const HOLDER_PRIV = '5555555555555555555555555555555555555555555555555555555555555555';
const HOLDER = 'did:example:holder';

class StaticResolver implements ResolverProvider {
  constructor(private readonly doc: DIDDocument) {}
  async resolveDocument(): Promise<DIDDocument> {
    return this.doc;
  }
}

function holderDid(): DIDDocument {
  const pubHex = bytesToHex(secp256k1.getPublicKey(hexToBytes(HOLDER_PRIV), false));
  return {
    '@context': [],
    id: HOLDER,
    verificationMethod: [
      {
        id: `${HOLDER}#key-1`,
        type: 'EcdsaSecp256k1VerificationKey2019',
        controller: HOLDER,
        publicKeyHex: pubHex,
      },
    ],
    authentication: [`${HOLDER}#key-1`],
    assertionMethod: [`${HOLDER}#key-1`],
  };
}

describe('VP challenge/domain', () => {
  const resolver = new StaticResolver(holderDid());

  it('binds JWT nonce/aud and rejects mismatches', async () => {
    const pres = await JWTPresentation.create(
      {
        context: ['https://www.w3.org/ns/credentials/v2'],
        types: ['VerifiablePresentation'],
        holder: HOLDER,
      },
      { verificationMethodKey: 'key-1', resolver, challenge: 'nonce-123', domain: 'verifier.example' },
    );
    await pres.addProofByProvider(new DefaultProvider(HOLDER_PRIV), { resolver });
    const token = await pres.serialize();
    await JWTPresentation.parse(token, {
      resolver,
      expectedChallenge: 'nonce-123',
      expectedDomain: 'verifier.example',
    });
    await expect(
      JWTPresentation.parse(token, { resolver, expectedChallenge: 'other' }),
    ).rejects.toMatchObject({ code: ErrorCode.ChallengeMismatch });
    await expect(
      JWTPresentation.parse(token, { resolver, expectedDomain: 'other.example' }),
    ).rejects.toMatchObject({ code: ErrorCode.DomainMismatch });
    await expect(
      JWTPresentation.parse(token, { resolver, requireAudience: true }),
    ).rejects.toMatchObject({ code: ErrorCode.AudienceUnbound });
  });

  it('binds JSON-LD proof challenge/domain', async () => {
    const pres = await JSONPresentation.create(
      {
        context: ['https://www.w3.org/ns/credentials/v2'],
        types: ['VerifiablePresentation'],
        holder: HOLDER,
      },
      { verificationMethodKey: 'key-1', resolver },
    );
    await pres.addProofByProvider(new DefaultProvider(HOLDER_PRIV), {
      resolver,
      verificationMethodKey: 'key-1',
      challenge: 'nonce-123',
      domain: 'verifier.example',
    });
    const out = await pres.serialize();
    await JSONPresentation.parse(JSON.stringify(out), {
      resolver,
      expectedChallenge: 'nonce-123',
      expectedDomain: 'verifier.example',
    });
    await expect(
      JSONPresentation.parse(JSON.stringify(out), { resolver, expectedChallenge: 'nope' }),
    ).rejects.toMatchObject({ code: ErrorCode.ChallengeMismatch });
  });
});
