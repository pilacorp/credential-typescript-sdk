/**
 * Go-parity signing / verification rules (review gaps 1.x, 3.x, 4.x):
 * proof-set append + verify-every-proof, per-proof DID, challenge/domain on every
 * proof, alg from the VM key, exp/nbf on proof verification, signer binding.
 */
import { p256 } from '@noble/curves/nist';
import { secp256k1 } from '@noble/curves/secp256k1';
import { addECDSAProof, addEcdsaSecp256k1Proof } from '../../src/common/jsonmap/jsonmap';
import { bytesToHex, hexToBytes } from '../../src/common/crypto/hex';
import { encodeBase58Btc } from '../../src/common/util/multibase';
import { DefaultProvider } from '../../src/common/signer/default-provider';
import { P256Provider } from '../../src/common/signer/p256-provider';
import { DIDDocument, ResolverProvider } from '../../src/common/verification-method';
import { encodeP256PublicMultibase } from '../../src/common/verification-method/multikey';
import { JSONCredential } from '../../src/vc/json-credential';
import { JOSECredential } from '../../src/vc/jose-credential';
import { JWTCredential } from '../../src/vc/jwt-credential';
import { JSONPresentation } from '../../src/vp/json-presentation';
import { JOSEPresentation } from '../../src/vp/jose-presentation';
import { parsePresentation } from '../../src/vp/presentation';

const A = 'did:example:a';
const B = 'did:example:b';
const SECP = '4646464646464646464646464646464646464646464646464646464646464646';
const P256 = '1111111111111111111111111111111111111111111111111111111111111111';
const V2 = 'https://www.w3.org/ns/credentials/v2';

class MapResolver implements ResolverProvider {
  constructor(private readonly docs: Record<string, DIDDocument>) {}
  async resolveDocument(did: string): Promise<DIDDocument> {
    const d = this.docs[did];
    if (!d) throw new Error(`no ${did}`);
    return d;
  }
}

function secpDoc(did: string, priv = SECP): DIDDocument {
  return {
    '@context': [],
    id: did,
    verificationMethod: [{
      id: `${did}#key-1`, type: 'EcdsaSecp256k1VerificationKey2019', controller: did,
      publicKeyHex: bytesToHex(secp256k1.getPublicKey(hexToBytes(priv), false)),
    }],
    authentication: [`${did}#key-1`],
    assertionMethod: [`${did}#key-1`],
  };
}

function p256Doc(did: string, priv = P256): DIDDocument {
  return {
    '@context': [],
    id: did,
    verificationMethod: [{
      id: `${did}#key-1`, type: 'Multikey', controller: did,
      publicKeyMultibase: encodeP256PublicMultibase(p256.getPublicKey(hexToBytes(priv), false)),
    }],
    authentication: [`${did}#key-1`],
    assertionMethod: [`${did}#key-1`],
  };
}

const contents = (issuer: string) => ({
  context: [V2],
  id: 'urn:uuid:x',
  types: ['VerifiableCredential'],
  issuer,
  subject: [{ id: 'did:example:s', customFields: { name: 'n' } }],
});

describe('JSON-LD proof set (4.6, 3.2, 4.7, 3.1, 3.4, 3.7, 3.8)', () => {
  const resolver = new MapResolver({ [A]: secpDoc(A), [B]: p256Doc(B) });

  async function twoProofs(): Promise<JSONCredential> {
    const cred = await JSONCredential.create(contents(A), { resolver });
    await cred.addProofByProvider(new DefaultProvider(SECP), { resolver });
    // A second, independent proof by another DID, appended to the set.
    await addECDSAProof(cred.getInternalData(), new P256Provider(P256), `${B}#key-1`, 'assertionMethod');
    return cred;
  }

  it('signing appends; verify checks every proof against the DID in its own verificationMethod', async () => {
    const cred = await twoProofs();
    const set = cred.getInternalData().proof as Record<string, unknown>[];
    expect(set).toHaveLength(2);
    await cred.verify({ resolver }); // body issuer is A, proof 2 names B: resolved per proof

    // Tamper the second proof: the whole set fails, but pinning the first passes.
    set[1].proofValue = 'z' + (set[1].proofValue as string).slice(1).split('').reverse().join('');
    await expect(cred.verify({ resolver })).rejects.toThrow();
    await cred.verify({ resolver, proofVerificationMethod: `${A}#key-1` });
    await expect(cred.verify({ resolver, proofVerificationMethod: `${A}#nope` })).rejects.toThrow(/no proof found/);
  });

  it('rejects a proof whose verificationMethod is not a DID URL', async () => {
    const cred = await JSONCredential.create(contents(A), { resolver });
    await cred.addProofByProvider(new DefaultProvider(SECP), { resolver });
    (cred.getInternalData().proof as Record<string, unknown>).verificationMethod = 'raw-key';
    await expect(cred.verify({ resolver })).rejects.toThrow(/not a DID URL/);
  });

  it('addProof(hex) is P-256; a secp256k1 VM needs an explicit DefaultProvider, and a wrong key is caught at signing', async () => {
    const b = await JSONCredential.create(contents(B), { resolver });
    await b.addProof(P256, { resolver });
    await b.verify({ resolver });

    const a = await JSONCredential.create(contents(A), { resolver });
    await expect(a.addProof(P256, { resolver })).rejects.toThrow(/does not verify against verification method/);
    expect(a.getInternalData().proof).toBeUndefined();
    expect((a.getInternalData()['@context'] as string[])).toEqual([V2]); // context restored
  });

  it('accepts an issuer given as { id } and refuses replaceProof on JSON-LD', async () => {
    const cred = await JSONCredential.create(contents(A), { resolver });
    cred.getInternalData().issuer = { id: A };
    await cred.addProofByProvider(new DefaultProvider(SECP), { resolver });
    await expect(cred.addProofByProvider(new DefaultProvider(SECP), { resolver, replaceProof: true }))
      .rejects.toThrow(/does not apply to JSON-LD/);
  });

  it('refuses a P-256 key under the secp256k1 suite (3.5)', async () => {
    const doc: Record<string, unknown> = { '@context': [V2], type: ['VerifiableCredential'], issuer: A, credentialSubject: { id: 'did:example:s' } };
    await expect(
      addEcdsaSecp256k1Proof(doc, new DefaultProvider(SECP), `${B}#key-1`, 'assertionMethod', {
        vmPublicKey: p256.getPublicKey(hexToBytes(P256), false),
      }),
    ).rejects.toThrow(/needs a secp256k1 key/);
    expect(doc['@context']).toEqual([V2]);
  });

  it('createProofSigning + addCustomProof round-trips for an external P-256 signer', async () => {
    const cred = await JSONCredential.create(contents(B), { resolver });
    const docHash = await cred.getSigningInput();
    const proof = {
      type: 'DataIntegrityProof', cryptosuite: 'ecdsa-rdfc-2019', created: '2025-01-01T00:00:00Z',
      verificationMethod: `${B}#key-1`, proofPurpose: 'assertionMethod',
    };
    // The data-integrity context must be present on the document for the proof config; V2 covers it.
    const digest = await cred.createProofSigning(docHash, proof);
    const sig = await new P256Provider(P256).sign(digest);
    const full = { ...proof, proofValue: encodeBase58Btc(sig) };
    await cred.addCustomProof(full, { resolver, verifyProof: true });
    await cred.verify({ resolver });
    // A proof signed over the wrong digest is refused and leaves nothing behind.
    const other = await JSONCredential.create({ ...contents(B), id: 'urn:uuid:other' }, { resolver });
    await expect(other.addCustomProof(full, { resolver, verifyProof: true })).rejects.toThrow(/does not verify/);
  });
});

describe('JSON VP challenge/domain on every proof (4.14)', () => {
  const resolver = new MapResolver({ [A]: secpDoc(A), [B]: p256Doc(B) });
  it('rejects when any verified proof has another challenge', async () => {
    const vp = await JSONPresentation.create(
      { context: [V2], types: ['VerifiablePresentation'], holder: A },
      { resolver },
    );
    await vp.addProofByProvider(new DefaultProvider(SECP), { resolver, challenge: 'c1', domain: 'd' });
    await addECDSAProof(vp['presentationData'], new P256Provider(P256), `${B}#key-1`, 'authentication', {
      challenge: 'other', domain: 'd',
    });
    await expect(vp.verify({ resolver, expectedChallenge: 'c1', expectedDomain: 'd' })).rejects.toThrow(/challenge/);
    // Pinned to the first proof only, the check passes.
    await vp.verify({ resolver, expectedChallenge: 'c1', expectedDomain: 'd', proofVerificationMethod: `${A}#key-1` });
  });
});

describe('JWT / JOSE (3.11-3.16, 3.17, 4.11, 4.12)', () => {
  const resolver = new MapResolver({ [A]: secpDoc(A), [B]: p256Doc(B) });

  function header(token: string): Record<string, unknown> {
    return JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString('utf8'));
  }

  it('alg follows the VM key for JWT VC, JOSE VC and JWT/JOSE VP; JOSE VC sets iat', async () => {
    for (const [did, priv, provider, alg] of [
      [A, SECP, () => new DefaultProvider(SECP), 'ES256K'],
      [B, P256, () => new P256Provider(P256), 'ES256'],
    ] as const) {
      const jwt = await JWTCredential.create(contents(did), { resolver });
      await jwt.addProofByProvider(provider(), {});
      expect(header((await jwt.serialize()) as string).alg).toBe(alg);
      await jwt.verify({ resolver });

      const jose = await JOSECredential.create(contents(did), { resolver });
      await jose.addProofByProvider(provider());
      const token = (await jose.serialize()) as string;
      expect(header(token).alg).toBe(alg);
      expect(typeof JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString()).iat).toBe('number');
      await jose.verify({ resolver });

      const vp = await JOSEPresentation.create({ context: [V2], types: ['VerifiablePresentation'], holder: did }, { resolver });
      expect(header(await vp.serialize()).alg).toBe(alg);
      expect(priv).toBeTruthy();
    }
  });

  it('JOSE VP errors on an RSA key instead of defaulting to ES256K', async () => {
    const rsaDoc: DIDDocument = {
      '@context': [], id: 'did:example:rsa',
      verificationMethod: [{ id: 'did:example:rsa#key-1', type: 'JsonWebKey2020', controller: 'did:example:rsa', publicKeyJwk: { kty: 'RSA', n: 'AQAB', e: 'AQAB' } }],
      authentication: ['did:example:rsa#key-1'], assertionMethod: ['did:example:rsa#key-1'],
    };
    await expect(
      JOSEPresentation.create(
        { context: [V2], types: ['VerifiablePresentation'], holder: 'did:example:rsa' },
        { resolver: new MapResolver({ 'did:example:rsa': rsaDoc }) },
      ),
    ).rejects.toThrow(/cannot sign a JWT/);
  });

  it('refuses re-signing without replaceProof, and refuses the kid option at sign time', async () => {
    const jose = await JOSECredential.create(contents(A), { resolver });
    await jose.addProofByProvider(new DefaultProvider(SECP));
    await expect(jose.addProofByProvider(new DefaultProvider(SECP))).rejects.toThrow(/already signed/);
    await expect(jose.addProofByProvider(new DefaultProvider(SECP), { verificationMethodKey: 'key-1', replaceProof: true }))
      .rejects.toThrow(/cannot be applied/);
    await jose.addProofByProvider(new DefaultProvider(SECP), { replaceProof: true });
  });

  it('JWT/JOSE addCustomProof checks the signature against the key', async () => {
    const jose = await JOSECredential.create(contents(A), { resolver });
    await expect(jose.addCustomProof({ signature: new Uint8Array(64).fill(7) } as never))
      .rejects.toThrow(/does not verify/);
    await expect(jose.addCustomProof({ signature: new Uint8Array(70) } as never)).rejects.toThrow(/64-byte/);
  });

  it('VP: nonce/aud are committed only after a successful sign', async () => {
    const vp = await JOSEPresentation.create({ context: [V2], types: ['VerifiablePresentation'], holder: A }, { resolver });
    const before = await vp.serialize();
    await expect(vp.addProofByProvider(new DefaultProvider(P256), { challenge: 'n', domain: 'd' })).rejects.toThrow();
    expect(await vp.serialize()).toBe(before);
  });

  it('vc+jwt verification always enforces exp/nbf; a 65-byte JWS signature is refused', async () => {
    const jose = await JOSECredential.create(
      { ...contents(A), validUntil: new Date(Date.now() + 60_000) },
      { resolver },
    );
    // Put an already-expired exp into the signed payload by building the token by hand.
    await jose.addProofByProvider(new DefaultProvider(SECP));
    const [h, p, s] = ((await jose.serialize()) as string).split('.');
    const payload = JSON.parse(Buffer.from(p, 'base64url').toString());
    payload.exp = Math.floor(Date.now() / 1000) - 3600;
    const p2 = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const { JWTSigner } = await import('../../src/common/jwt/signer');
    const sig = await new JWTSigner(new DefaultProvider(SECP)).signString(`${h}.${p2}`);
    const expired = await JOSECredential.parse(`${h}.${p2}.${sig}`);
    await expect(expired.verify({ resolver })).rejects.toThrow(/expired/);

    // 65 bytes (r||s||v) in the token itself.
    const sig65 = Buffer.concat([Buffer.from(s, 'base64url'), Buffer.from([0])]).toString('base64url');
    const long = await JOSECredential.parse(`${h}.${p}.${sig65}`);
    await expect(long.verify({ resolver })).rejects.toThrow(/signature length/);
  });
});

describe('parse-time rules (1.7, 1.8, 1.10, 1.11, 4.19)', () => {
  it('JSONCredential.parse requires @context, type, issuer, credentialSubject', async () => {
    await expect(JSONCredential.parse(JSON.stringify({ '@context': [V2], type: 'VerifiableCredential', issuer: A })))
      .rejects.toThrow(/missing credentialSubject/);
  });

  it('parsePresentation names SD-JWT-shaped input', async () => {
    await expect(parsePresentation('aaa.bbb.ccc~disclosure~')).rejects.toThrow(/SD-JWT/);
  });

  it('a verifiableCredential given as a single object is parsed, not ignored', async () => {
    const resolver = new MapResolver({ [A]: secpDoc(A) });
    const vcCred = await JSONCredential.create(contents(A), { resolver });
    await vcCred.addProofByProvider(new DefaultProvider(SECP), { resolver });
    const vp = await JSONPresentation.create(
      { context: [V2], types: ['VerifiablePresentation'], holder: A, verifiableCredentials: [vcCred] },
      { resolver },
    );
    const data = vp['presentationData'];
    data.verifiableCredential = (data.verifiableCredential as unknown[])[0]; // single object form
    // validateVC reaches the embedded credential; with a bad proof it must fail (so it was parsed).
    ((data.verifiableCredential as Record<string, unknown>).proof as Record<string, unknown>).jws = 'a..b';
    await expect(vp.executeOptions({ resolver, validateVC: true })).rejects.toThrow(/failed to verify credential at index 0/);
  });
});

describe('JOSE parse/create guards (4.9, 4.10, 3.18) and misc (1.9, 4.19)', () => {
  const resolver = new MapResolver({ [A]: secpDoc(A) });
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const token = (typ: string, payload: unknown) => `${b64({ typ, alg: 'ES256K', kid: `${A}#key-1` })}.${b64(payload)}.sig`;
  const vcPayload = { '@context': [V2], type: ['VerifiableCredential'], issuer: A, credentialSubject: { id: 'did:example:s' } };

  it('refuses making top-level claims disclosable at create', async () => {
    await expect(JOSECredential.create(contents(A), { resolver, sdSelectivePaths: ['issuer'] }))
      .rejects.toThrow();
    const ok = await JOSECredential.create(contents(A), { resolver, sdSelectivePaths: ['credentialSubject.name'] });
    expect(ok.isDisclosable()).toBe(true);
  });

  it('create validates caller-built disclosures', async () => {
    await expect(
      JOSECredential.create(contents(A), { resolver, sdDisclosures: [Buffer.from('["s","k","v"]').toString('base64url')] }),
    ).rejects.toThrow(/invalid SD-JWT disclosures/);
  });

  it('parse: typ must match the SD shape, v2 context first, properties present', async () => {
    await expect(JOSECredential.parse(token('vc+jwt', { ...vcPayload, _sd_alg: 'sha-256' })))
      .rejects.toThrow(/does not match the SD-JWT format/);
    await expect(JOSECredential.parse(token('vc+jwt', { ...vcPayload, '@context': ['https://www.w3.org/2018/credentials/v1'] })))
      .rejects.toThrow(/@context/);
    await expect(JOSECredential.parse(token('vc+jwt', { ...vcPayload, credentialSubject: undefined })))
      .rejects.toThrow(/missing credentialSubject/);
    await expect(JOSECredential.parse(token('vc+jwt', { ...vcPayload, _sd: ['x'] })))
      .rejects.toThrow(/_sd at the root/);
  });

  it('parse: an SD-JWT whose digests are present reconstructs even without _sd_alg (4.10)', async () => {
    const sdTok = token('vc+sd-jwt', { ...vcPayload, credentialSubject: { id: 'did:example:s', _sd: [] } }) + '~';
    const parsed = await JOSECredential.parse(sdTok);
    expect(parsed.extractField('credentialSubject._sd')).toBeNull();
  });

  it('credentialStatus[i].type is required when serializing contents', async () => {
    await expect(JSONCredential.create({ ...contents(A), credentialStatus: [{ type: '' }] }, { resolver }))
      .rejects.toThrow(/credentialStatus\[0\]\.type is required/);
  });

  it('SD-JWT key binding JWT is refused (1.11)', async () => {
    const kb = `${b64({ alg: 'ES256K' })}.${b64({ nonce: 1 })}.sig`;
    await expect(JOSECredential.parse(token('vc+sd-jwt', vcPayload) + '~WyJhIiwiYiIsImMiXQ~' + kb)).rejects.toThrow(/key binding/);
  });
});
