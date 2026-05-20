/**
 * End-to-end secp256k1 JWT sign + verify with a stub DID resolver,
 * mirroring credential/common/jwt/signer_test.go and verifier_test.go.
 */
import { secp256k1 } from '@noble/curves/secp256k1';
import { DefaultProvider } from '../../src/common/signer/default-provider';
import { JWTSigner } from '../../src/common/jwt/signer';
import { JWTVerifier } from '../../src/common/jwt/verifier';
import { bytesToHex, hexToBytes } from '../../src/common/crypto/hex';
import {
  DIDDocument,
  ResolverProvider,
} from '../../src/common/verification-method';

const PRIV_HEX = '4646464646464646464646464646464646464646464646464646464646464646';
const DID = 'did:example:test';

class StaticResolver implements ResolverProvider {
  constructor(private readonly doc: DIDDocument) {}
  async resolveDocument(): Promise<DIDDocument> {
    return this.doc;
  }
}

function buildDID(): DIDDocument {
  const priv = hexToBytes(PRIV_HEX);
  const pubUncompressed = secp256k1.getPublicKey(priv, false);
  const pubHex = bytesToHex(pubUncompressed);
  return {
    '@context': [],
    id: DID,
    verificationMethod: [
      {
        id: `${DID}#key-1`,
        type: 'EcdsaSecp256k1VerificationKey2019',
        controller: DID,
        publicKeyHex: pubHex,
      },
    ],
    authentication: [`${DID}#key-1`],
    assertionMethod: [`${DID}#key-1`],
  };
}

function buildJWT(signingInput: string, signature: string): string {
  return signingInput + '.' + signature;
}

describe('JWT sign + verify roundtrip (ES256K)', () => {
  it('verifies a VC JWT signed with DefaultProvider', async () => {
    const signer = new DefaultProvider(PRIV_HEX);
    const jwtSigner = new JWTSigner(signer);

    const header = { typ: 'JWT', alg: 'ES256K', kid: `${DID}#key-1` };
    const payload = {
      iss: DID,
      vc: { '@context': [], type: 'VerifiableCredential' },
    };
    const headerB64 = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
    const payloadB64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
    const signingInput = headerB64 + '.' + payloadB64;
    const signature = await jwtSigner.signString(signingInput);

    const token = buildJWT(signingInput, signature);

    const verifier = new JWTVerifier(new StaticResolver(buildDID()));
    await expect(verifier.verifyJWT(token)).resolves.toBeUndefined();
  });

  it('rejects a JWT signed with the wrong key', async () => {
    const signer = new DefaultProvider(
      '7777777777777777777777777777777777777777777777777777777777777777',
    );
    const jwtSigner = new JWTSigner(signer);

    const header = { typ: 'JWT', alg: 'ES256K', kid: `${DID}#key-1` };
    const payload = { iss: DID, vc: {} };
    const headerB64 = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
    const payloadB64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
    const signingInput = headerB64 + '.' + payloadB64;
    const signature = await jwtSigner.signString(signingInput);
    const token = buildJWT(signingInput, signature);

    const verifier = new JWTVerifier(new StaticResolver(buildDID()));
    await expect(verifier.verifyJWT(token)).rejects.toThrow();
  });

  it('rejects token whose kid is missing in the DID document', async () => {
    const signer = new DefaultProvider(PRIV_HEX);
    const jwtSigner = new JWTSigner(signer);
    const header = { typ: 'JWT', alg: 'ES256K', kid: `${DID}#key-9` };
    const payload = { iss: DID, vc: {} };
    const headerB64 = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
    const payloadB64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
    const token = buildJWT(headerB64 + '.' + payloadB64, await jwtSigner.signString(headerB64 + '.' + payloadB64));
    const verifier = new JWTVerifier(new StaticResolver(buildDID()));
    await expect(verifier.verifyJWT(token)).rejects.toThrow(/not found/);
  });
});
