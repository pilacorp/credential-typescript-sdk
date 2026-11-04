/**
 * JOSE verifiable presentation (vp+jwt) — port of vp/jose_presentation_test.go.
 *
 * Covers the vc-jose-cose presentation: holder binding through the shared JWT
 * verifier (purpose=authentication), the EnvelopedVerifiableCredential wrapping
 * of embedded credentials, challenge/domain binding, and parser routing by typ.
 */
import { secp256k1 } from '@noble/curves/secp256k1';
import { bytesToHex, hexToBytes } from '../../src/common/crypto/hex';
import { DefaultProvider } from '../../src/common/signer/default-provider';
import { DIDDocument, ResolverProvider } from '../../src/common/verification-method';
import { JOSECredential } from '../../src/vc/jose-credential';
import { JOSEPresentation } from '../../src/vp/jose-presentation';
import { parsePresentation } from '../../src/vp/presentation';

const ISSUER = 'did:example:issuer';
const HOLDER = 'did:example:holder';
const ISSUER_PRIV = '4646464646464646464646464646464646464646464646464646464646464646';
const HOLDER_PRIV = '5555555555555555555555555555555555555555555555555555555555555555';
const ATTACKER_PRIV = '7777777777777777777777777777777777777777777777777777777777777777';
const V2 = 'https://www.w3.org/ns/credentials/v2';

class MapResolver implements ResolverProvider {
  constructor(private readonly docs: Record<string, DIDDocument>) {}
  async resolveDocument(did: string): Promise<DIDDocument> {
    const doc = this.docs[did];
    if (!doc) throw new Error(`unknown DID: ${did}`);
    return doc;
  }
}

function secpDoc(did: string, priv: string): DIDDocument {
  const pubHex = bytesToHex(secp256k1.getPublicKey(hexToBytes(priv), false));
  return {
    '@context': [],
    id: did,
    verificationMethod: [
      { id: `${did}#key-1`, type: 'EcdsaSecp256k1VerificationKey2019', controller: did, publicKeyHex: pubHex },
    ],
    authentication: [`${did}#key-1`],
    assertionMethod: [`${did}#key-1`],
  };
}

const resolver = new MapResolver({
  [ISSUER]: secpDoc(ISSUER, ISSUER_PRIV),
  [HOLDER]: secpDoc(HOLDER, HOLDER_PRIV),
});

async function signedCredential(): Promise<JOSECredential> {
  const cred = await JOSECredential.create(
    { context: [V2], types: ['VerifiableCredential'], issuer: ISSUER, subject: [{ id: HOLDER }] },
    { verificationMethodKey: 'key-1', resolver },
  );
  await cred.addProofByProvider(new DefaultProvider(ISSUER_PRIV), { resolver });
  return cred;
}

function decodeHeader(token: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString('utf8'));
}
function decodePayload(token: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
}

describe('JOSEPresentation (vp+jwt)', () => {
  it('round-trips sign + verify with holder binding', async () => {
    const vp = await JOSEPresentation.create(
      { context: [V2], types: ['VerifiablePresentation'], holder: HOLDER },
      { verificationMethodKey: 'key-1', resolver },
    );
    await vp.addProofByProvider(new DefaultProvider(HOLDER_PRIV), { resolver });
    const token = await vp.serialize();

    expect(decodeHeader(token).typ).toBe('vp+jwt');
    expect(decodePayload(token).vp).toBeUndefined();
    expect(decodePayload(token).holder).toBe(HOLDER);

    const parsed = await JOSEPresentation.parse(token, { resolver });
    expect(parsed.getType()).toBe('JOSE');
    await expect(parsed.verify({ resolver })).resolves.toBeUndefined();
  });

  it('wraps embedded credentials as EnvelopedVerifiableCredential', async () => {
    const cred = await signedCredential();
    const vp = await JOSEPresentation.create(
      {
        context: [V2],
        types: ['VerifiablePresentation'],
        holder: HOLDER,
        verifiableCredentials: [cred],
      },
      { verificationMethodKey: 'key-1', resolver },
    );
    await vp.addProofByProvider(new DefaultProvider(HOLDER_PRIV), { resolver });
    const token = await vp.serialize();

    const vcList = decodePayload(token).verifiableCredential as Array<Record<string, unknown>>;
    expect(Array.isArray(vcList)).toBe(true);
    expect(vcList[0].type).toContain('EnvelopedVerifiableCredential');
    expect(vcList[0].id).toMatch(/^data:application\/vc\+jwt,/);

    // parse enforces requireEnvelopedCredentials and holder binding.
    await expect(parsePresentation(token, { resolver })).resolves.toBeDefined();
    const parsed = await JOSEPresentation.parse(token, { resolver });
    await expect(parsed.verify({ resolver })).resolves.toBeUndefined();
  });

  it('refuses a Data Integrity (non-JOSE) credential in a vp+jwt', async () => {
    const { JSONCredential } = await import('../../src/vc/json-credential');
    const jsonCred = await JSONCredential.create(
      { context: [V2], types: ['VerifiableCredential'], issuer: ISSUER, subject: [{ id: HOLDER }] },
      { verificationMethodKey: 'key-1', resolver },
    );
    await jsonCred.addProofByProvider(new DefaultProvider(ISSUER_PRIV), { resolver });
    await expect(
      JOSEPresentation.create(
        { context: [V2], types: ['VerifiablePresentation'], holder: HOLDER, verifiableCredentials: [jsonCred] },
        { verificationMethodKey: 'key-1', resolver },
      ),
    ).rejects.toThrow(/enveloping-secured/);
  });

  it('rejects a vp+jwt signed by a key that is not the holder key', async () => {
    const vp = await JOSEPresentation.create(
      { context: [V2], types: ['VerifiablePresentation'], holder: HOLDER },
      { verificationMethodKey: 'key-1', resolver },
    );
    // kid in the header is holder#key-1, but we sign with the attacker's key.
    await vp.addProofByProvider(new DefaultProvider(ATTACKER_PRIV), { resolver });
    const token = await vp.serialize();
    const parsed = await JOSEPresentation.parse(token, { resolver });
    await expect(parsed.verify({ resolver })).rejects.toThrow();
  });

  it('binds challenge and domain, and checks them on verify', async () => {
    const vp = await JOSEPresentation.create(
      { context: [V2], types: ['VerifiablePresentation'], holder: HOLDER },
      { verificationMethodKey: 'key-1', resolver, challenge: 'n-123', domain: 'https://verifier.example' },
    );
    await vp.addProofByProvider(new DefaultProvider(HOLDER_PRIV), { resolver });
    const token = await vp.serialize();

    expect(decodePayload(token).nonce).toBe('n-123');
    expect(decodePayload(token).aud).toBe('https://verifier.example');

    const parsed = await JOSEPresentation.parse(token, { resolver });
    await expect(
      parsed.verify({ resolver, expectedChallenge: 'n-123', expectedDomain: 'https://verifier.example' }),
    ).resolves.toBeUndefined();

    const parsed2 = await JOSEPresentation.parse(token, { resolver });
    await expect(parsed2.verify({ resolver, expectedDomain: 'https://attacker.example' })).rejects.toThrow();
  });

  it('refuses a vp+jwt whose payload carries a bare (non-enveloped) credential', async () => {
    const header = Buffer.from(JSON.stringify({ typ: 'vp+jwt', alg: 'ES256K', kid: `${HOLDER}#key-1` }), 'utf8').toString('base64url');
    const payload = Buffer.from(
      JSON.stringify({ '@context': [V2], type: ['VerifiablePresentation'], holder: HOLDER, verifiableCredential: ['eyJ.eyJ.sig'] }),
      'utf8',
    ).toString('base64url');
    await expect(JOSEPresentation.parse(`${header}.${payload}.AAAA`, { resolver })).rejects.toThrow(/EnvelopedVerifiableCredential/);
  });

  it('refuses a payload that carries a vp claim', async () => {
    const header = Buffer.from(JSON.stringify({ typ: 'vp+jwt', alg: 'ES256K', kid: `${HOLDER}#key-1` }), 'utf8').toString('base64url');
    const payload = Buffer.from(JSON.stringify({ '@context': [V2], type: ['VerifiablePresentation'], holder: HOLDER, vp: {} }), 'utf8').toString('base64url');
    await expect(JOSEPresentation.parse(`${header}.${payload}.AAAA`, { resolver })).rejects.toThrow(/'vp' claim MUST NOT/);
  });

  it('routes a vp+jwt token through JOSEPresentation in parsePresentation', async () => {
    const vp = await JOSEPresentation.create(
      { context: [V2], types: ['VerifiablePresentation'], holder: HOLDER },
      { verificationMethodKey: 'key-1', resolver },
    );
    await vp.addProofByProvider(new DefaultProvider(HOLDER_PRIV), { resolver });
    const token = await vp.serialize();
    const parsed = await parsePresentation(token, { resolver });
    expect(parsed.getType()).toBe('JOSE');
  });
});
