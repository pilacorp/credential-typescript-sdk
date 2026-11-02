import { p256 } from '@noble/curves/nist';
import { bytesToHex, hexToBytes } from '../../src/common/crypto/hex';
import { P256Provider } from '../../src/common/signer/p256-provider';
import {
  DIDDocument,
  ResolverProvider,
} from '../../src/common/verification-method';
import { encodeP256PublicMultibase } from '../../src/common/verification-method/multikey';
import { JSONCredential } from '../../src/vc/json-credential';
import { JOSECredential, TypeVCJWT } from '../../src/vc/jose-credential';
import { parseCredential } from '../../src/vc/credential';
import { DefaultProvider } from '../../src/common/signer/default-provider';
import { secp256k1 } from '@noble/curves/secp256k1';

const ISSUER = 'did:example:p256-issuer';
const SUBJECT = 'did:example:subject';
const P256_PRIV = '1111111111111111111111111111111111111111111111111111111111111111';
const SECP_PRIV = '4646464646464646464646464646464646464646464646464646464646464646';

class StaticResolver implements ResolverProvider {
  constructor(private readonly doc: DIDDocument) {}
  async resolveDocument(): Promise<DIDDocument> {
    return this.doc;
  }
}

function p256Did(): DIDDocument {
  const pub = p256.getPublicKey(hexToBytes(P256_PRIV), false);
  return {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/v1',
      'https://www.w3.org/ns/cid/v1',
    ],
    id: ISSUER,
    verificationMethod: [
      {
        id: `${ISSUER}#key-2`,
        type: 'Multikey',
        controller: ISSUER,
        publicKeyMultibase: encodeP256PublicMultibase(pub),
      },
    ],
    authentication: [`${ISSUER}#key-2`],
    assertionMethod: [`${ISSUER}#key-2`],
  };
}

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

describe('P-256 JSON-LD Data Integrity', () => {
  it('rejects P-256 private keys outside 1..n-1', () => {
    expect(() => new P256Provider('00'.repeat(32))).toThrow(/curve order/);
  });

  it('signs and verifies ecdsa-rdfc-2019 against a Multikey DID', async () => {
    const resolver = new StaticResolver(p256Did());
    const cred = await JSONCredential.create(
      {
        context: ['https://www.w3.org/ns/credentials/v2'],
        id: 'urn:uuid:p256',
        types: ['VerifiableCredential'],
        issuer: ISSUER,
        subject: [{ id: SUBJECT, customFields: { name: 'P256' } }],
      },
      { verificationMethodKey: 'key-2', resolver },
    );
    await cred.addProofByProvider(new P256Provider(P256_PRIV), {
      verificationMethodKey: 'key-2',
      resolver,
    });
    const out = await cred.serialize();
    const proof = (out as Record<string, unknown>).proof as Record<string, string>;
    expect(proof.proofValue.startsWith('z')).toBe(true);
    expect(proof.cryptosuite).toBe('ecdsa-rdfc-2019');
    await JSONCredential.parse(JSON.stringify(out), { resolver, verifyProof: true });
  });
});

describe('JOSECredential vc+jwt', () => {
  it('issues a flat vc+jwt payload and parseCredential routes to JOSECredential', async () => {
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
    const token = await cred.serialize();
    const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString('utf8'));
    expect(header.typ).toBe(TypeVCJWT);
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
    expect(payload.vc).toBeUndefined();
    expect(payload.issuer).toBe(ISSUER);

    const parsed = await parseCredential(token, { resolver, verifyProof: true });
    expect(parsed.getType()).toBe('JOSE');
  });

  it('refuses a vc+jwt token that still wraps a vc claim', async () => {
    const header = Buffer.from(JSON.stringify({ typ: 'vc+jwt', alg: 'ES256K', kid: `${ISSUER}#key-1` })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ vc: { issuer: ISSUER }, iss: ISSUER })).toString('base64url');
    await expect(JOSECredential.parse(`${header}.${payload}.sig`)).rejects.toThrow(/vc or vp/);
  });
});
