/**
 * End-to-end VP issuance & verification — abbreviated port of vp/presentation_test.go.
 *
 * Note on the fetch mock: like Go's serializePresentationContents, our
 * port calls `vc.verify()` (no options) at VP-build time, which routes
 * through the SDK's *default* HTTPResolver. We install a global fetch
 * stub that serves the issuer/holder DID Documents so this inner call
 * succeeds without hitting the network.
 */
import { DefaultProvider } from '../../src/common/signer/default-provider';
import { secp256k1 } from '@noble/curves/secp256k1';
import { bytesToHex, hexToBytes } from '../../src/common/crypto/hex';
import {
  DIDDocument,
  ResolverProvider,
} from '../../src/common/verification-method';
import { JWTCredential } from '../../src/vc/jwt-credential';
import { JSONCredential } from '../../src/vc/json-credential';
import { JWTPresentation } from '../../src/vp/jwt-presentation';
import { JSONPresentation } from '../../src/vp/json-presentation';

const ISSUER_PRIV = '4646464646464646464646464646464646464646464646464646464646464646';
const HOLDER_PRIV = '5555555555555555555555555555555555555555555555555555555555555555';
const ISSUER = 'did:example:issuer';
const HOLDER = 'did:example:holder';
const SUBJECT = HOLDER;

class StaticResolver implements ResolverProvider {
  constructor(private readonly docs: Record<string, DIDDocument>) {}
  async resolveDocument(did: string): Promise<DIDDocument> {
    const doc = this.docs[did];
    if (!doc) throw new Error(`unknown DID: ${did}`);
    return doc;
  }
}

function buildIssuerDID(): DIDDocument {
  const pubHex = bytesToHex(
    secp256k1.getPublicKey(hexToBytes(ISSUER_PRIV), false),
  );
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

function buildHolderDID(): DIDDocument {
  const pubHex = bytesToHex(
    secp256k1.getPublicKey(hexToBytes(HOLDER_PRIV), false),
  );
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

const docsByDID: Record<string, DIDDocument> = {};

beforeAll(() => {
  docsByDID[ISSUER] = buildIssuerDID();
  docsByDID[HOLDER] = buildHolderDID();
  jest.spyOn(global, 'fetch').mockImplementation(async (input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString();
    const did = decodeURIComponent(url.split('/').pop() ?? '');
    const doc = docsByDID[did];
    if (!doc) {
      return new Response('not found', { status: 404 });
    }
    return new Response(JSON.stringify(doc), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  });
});

afterAll(() => {
  jest.restoreAllMocks();
});

describe('JWTPresentation roundtrip', () => {
  it('issues a presentation embedding a JWT VC and verifies the signature', async () => {
    const resolver = new StaticResolver(docsByDID);

    const vc = await JWTCredential.create(
      {
        context: ['https://www.w3.org/ns/credentials/v2'],
        id: 'urn:uuid:vc',
        types: ['VerifiableCredential'],
        issuer: ISSUER,
        validFrom: new Date('2024-01-01T00:00:00Z'),
        subject: [{ id: SUBJECT, customFields: { name: 'Alice' } }],
      },
      { verificationMethodKey: 'key-1', resolver },
    );
    await vc.addProof(ISSUER_PRIV);

    const vp = await JWTPresentation.create(
      {
        context: ['https://www.w3.org/ns/credentials/v2'],
        id: 'urn:uuid:vp',
        types: ['VerifiablePresentation'],
        holder: HOLDER,
        validFrom: new Date('2024-02-01T00:00:00Z'),
        verifiableCredentials: [vc],
      },
      { verificationMethodKey: 'key-1', resolver },
    );
    await vp.addProof(HOLDER_PRIV);

    const token = (await vp.serialize()) as string;
    expect(typeof token).toBe('string');

    const parsed = await JWTPresentation.parse(token, { resolver });
    await parsed.verify({ resolver });
  });
});

describe('JSONPresentation roundtrip', () => {
  it('addCustomProof appends and does not re-verify the existing proof set', async () => {
    const resolver = new StaticResolver(docsByDID);
    const vp = await JSONPresentation.create(
      { context: ['https://www.w3.org/ns/credentials/v2'], id: 'urn:uuid:replace', types: ['VerifiablePresentation'], holder: HOLDER },
      { verificationMethodKey: 'key-1', resolver },
    );
    await vp.addProofByProvider(new DefaultProvider(HOLDER_PRIV), { verificationMethodKey: 'key-1', resolver });
    const base = {
      type: 'DataIntegrityProof',
      cryptosuite: 'ecdsa-rdfc-2019',
      created: '2024-01-01T00:00:00Z',
      verificationMethod: `${HOLDER}#key-1`,
      proofPurpose: 'authentication',
    };
    await expect(vp.addCustomProof({ ...base, proofValue: 'deadbeef' }, { resolver })).rejects.toThrow(/base58btc/);
    await expect(vp.addCustomProof({ ...base, proofValue: 'zabc' }, { resolver, challenge: 'c' }))
      .rejects.toThrow(/cannot be applied by addCustomProof/);
    await vp.addCustomProof({ ...base, proofValue: 'zabc', challenge: 'c1' }, { resolver });
    expect(((await vp.serialize()).proof as unknown[]).length).toBe(2);
  });

  it('attaches an ECDSA proof and verifies it', async () => {
    const resolver = new StaticResolver(docsByDID);

    const vc = await JSONCredential.create(
      {
        context: ['https://www.w3.org/ns/credentials/v2'],
        id: 'urn:uuid:vc',
        types: ['VerifiableCredential'],
        issuer: ISSUER,
        validFrom: new Date('2024-01-01T00:00:00Z'),
        subject: [{ id: SUBJECT, customFields: { name: 'Carol' } }],
      },
      { verificationMethodKey: 'key-1', resolver },
    );
    await vc.addProofByProvider(new DefaultProvider(ISSUER_PRIV), { verificationMethodKey: 'key-1', resolver });

    const vp = await JSONPresentation.create(
      {
        context: ['https://www.w3.org/ns/credentials/v2'],
        id: 'urn:uuid:vp',
        types: ['VerifiablePresentation'],
        holder: HOLDER,
        verifiableCredentials: [vc],
      },
      { verificationMethodKey: 'key-1', resolver },
    );
    await vp.addProofByProvider(new DefaultProvider(HOLDER_PRIV), { verificationMethodKey: 'key-1', resolver });

    const serialized = await vp.serialize();
    expect((serialized as Record<string, unknown>).proof).toBeTruthy();
    await vp.verify({ resolver });
  });
});
