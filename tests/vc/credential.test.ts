/**
 * End-to-end VC issuance & verification — port of vc/credential_test.go.
 * Uses a stub DID resolver so tests don't hit the network.
 */
import { DefaultProvider } from '../../src/common/signer/default-provider';
import { secp256k1 } from '@noble/curves/secp256k1';
import { compressToBase64URL } from '../../src/common/util/compress';
import { bytesToHex, hexToBytes } from '../../src/common/crypto/hex';
import {
  DIDDocument,
  ResolverProvider,
} from '../../src/common/verification-method';
import { parseCredential } from '../../src/vc/credential';
import { JWTCredential } from '../../src/vc/jwt-credential';
import { JOSECredential } from '../../src/vc/jose-credential';
import { isSDJWTRequiresJOSE } from '../../src/vc/errors';
import { JSONCredential } from '../../src/vc/json-credential';

const PRIV_HEX = '4646464646464646464646464646464646464646464646464646464646464646';
const ISSUER = 'did:example:issuer';
const SUBJECT = 'did:example:subject';
const STATUS_LIST_URL =
  'https://auth-dev.pila.vn/api/v1/issuers/did:pila:testnet:0xedf82c5366eeffcbef566b2edffab102d140f212/credentials/status/366';

class StaticResolver implements ResolverProvider {
  constructor(private readonly doc: DIDDocument) {}
  async resolveDocument(): Promise<DIDDocument> {
    return this.doc;
  }
}

function buildDID(): DIDDocument {
  const priv = hexToBytes(PRIV_HEX);
  const pubHex = bytesToHex(secp256k1.getPublicKey(priv, false));
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

beforeAll(() => {
  jest.spyOn(global, 'fetch').mockImplementation(async (input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url === STATUS_LIST_URL) {
      return new Response(
        JSON.stringify({
          data: {
            '@context': ['https://www.w3.org/ns/credentials/status/v1'],
            credentialSubject: {
              encodedList: compressToBase64URL(new Uint8Array(121)),
              id: `${STATUS_LIST_URL}#list`,
              statusPurpose: 'revocation',
              type: 'BitstringStatusList',
            },
            id: STATUS_LIST_URL,
            issuer: ISSUER,
            proof: {},
            type: ['VerifiableCredential', 'BitstringStatusListCredential'],
            validFrom: '2024-01-01T00:00:00Z',
            validUntil: '2099-01-01T00:00:00Z',
          },
        }),
        {
          status: 200,
          headers: { 'content-type': 'application/json' },
        },
      );
    }
    return new Response('not found', { status: 404 });
  });
});

afterAll(() => {
  jest.restoreAllMocks();
});

describe('parseCredential', () => {
  it('parses a JSON credential', async () => {
    const json = JSON.stringify({
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      id: 'urn:uuid:1234',
      type: ['VerifiableCredential'],
      issuer: ISSUER,
      validFrom: '2025-08-05T10:00:00Z',
      credentialSubject: { id: SUBJECT, name: 'John Doe' },
      proof: { type: 'Ed25519Signature2020', created: '2025-08-05T10:00:00Z', proofValue: 'sig' },
    });
    const cred = await parseCredential(json);
    expect(cred.getType()).toBe('JSON');
    expect(cred.extractField('credentialSubject.name')).toBe('John Doe');
  });

  it('rejects empty input', async () => {
    await expect(parseCredential('')).rejects.toThrow(/empty/);
  });

  it('rejects invalid JSON / token', async () => {
    await expect(parseCredential('{invalid}')).rejects.toThrow();
  });
});

describe('JWTCredential.create + verify roundtrip', () => {
  it('issues a JWT VC and verifies the signature', async () => {
    const cred = await JWTCredential.create(
      {
        context: ['https://www.w3.org/ns/credentials/v2'],
        id: 'urn:uuid:test',
        types: ['VerifiableCredential'],
        issuer: ISSUER,
        validFrom: new Date('2024-01-01T00:00:00Z'),
        validUntil: new Date('2099-01-01T00:00:00Z'),
        subject: [{ id: SUBJECT, customFields: { name: 'Alice' } }],
      },
      {
        verificationMethodKey: 'key-1',
        resolver: new StaticResolver(buildDID()),
      },
    );

    await cred.addProof(PRIV_HEX);

    const token = await cred.serialize();
    expect(typeof token).toBe('string');

    const parsed = await JWTCredential.parse(token as string, {
      resolver: new StaticResolver(buildDID()),
    });
    await parsed.verify({ resolver: new StaticResolver(buildDID()) });
  });

  it('refuses selective disclosure on the VC 1.1 JWT path (ErrSDJWTRequiresJOSE)', async () => {
    const resolver = new StaticResolver(buildDID());
    const contents = {
      context: ['https://www.w3.org/ns/credentials/v2'],
      id: 'urn:uuid:sd',
      types: ['VerifiableCredential'],
      issuer: ISSUER,
      subject: [{ id: SUBJECT, customFields: { name: 'Bob', secret: 's3cr3t' } }],
    };
    const err = await JWTCredential.create(contents, {
      verificationMethodKey: 'key-1',
      resolver,
      sdSelectivePaths: ['credentialSubject.secret'],
    }).catch((e) => e);
    expect(isSDJWTRequiresJOSE(err)).toBe(true);

    // The same call on JOSE issues vc+sd-jwt, which JWTCredential.parse refuses.
    const jose = await JOSECredential.create(contents, {
      verificationMethodKey: 'key-1',
      resolver,
      sdSelectivePaths: ['credentialSubject.secret'],
    });
    await jose.addProof(PRIV_HEX);
    const token = (await jose.serialize()) as string;
    expect(token.includes('~')).toBe(true);
    const parseErr = await JWTCredential.parse(token, { resolver }).catch((e) => e);
    expect(isSDJWTRequiresJOSE(parseErr)).toBe(true);
    expect(isSDJWTRequiresJOSE(await jose.present([]).catch((e) => e))).toBe(false);
  });

  it('refuses to sign twice without replaceProof, and rejects a signer that is not the VM key', async () => {
    const resolver = new StaticResolver(buildDID());
    const contents = {
      context: ['https://www.w3.org/2018/credentials/v1'],
      id: 'urn:uuid:twice',
      types: ['VerifiableCredential'],
      issuer: ISSUER,
      subject: [{ id: SUBJECT }],
    };
    const cred = await JWTCredential.create(contents, { verificationMethodKey: 'key-1', resolver });
    await expect(cred.addProof('1111111111111111111111111111111111111111111111111111111111111111'))
      .rejects.toThrow(/does not verify against verification method/);
    await cred.addProof(PRIV_HEX);
    const first = await cred.serialize();
    await expect(cred.addProof(PRIV_HEX)).rejects.toThrow(/already signed/);
    await expect(cred.addProof(PRIV_HEX, { verificationMethodKey: 'key-1', replaceProof: true }))
      .rejects.toThrow(/cannot be applied/);
    await cred.addProof(PRIV_HEX, { replaceProof: true });
    expect(await cred.serialize()).toBe(first); // RFC 6979: deterministic
    expect(await cred.hash()).toMatch(/^[0-9a-f]{64}$/);
  });

  it('reports "not signed" when verifying an unsigned JWT credential', async () => {
    const resolver = new StaticResolver(buildDID());
    const cred = await JWTCredential.create(
      { context: ['https://www.w3.org/2018/credentials/v1'], id: 'urn:uuid:u', types: ['VerifiableCredential'], issuer: ISSUER, subject: [{ id: SUBJECT }] },
      { verificationMethodKey: 'key-1', resolver },
    );
    await expect(cred.verify({ resolver })).rejects.toThrow(/not signed/);
    await expect(cred.hash()).rejects.toThrow(/signed before hashing/);
  });
});

describe('JSONCredential.create + verify roundtrip', () => {
  it('addCustomProof appends (keeping every proof field), refuses hex rdfc proofs and never re-verifies the set', async () => {
    const resolver = new StaticResolver(buildDID());
    const cred = await JSONCredential.create(
      { context: ['https://www.w3.org/ns/credentials/v2'], id: 'urn:uuid:replace', types: ['VerifiableCredential'], issuer: ISSUER, subject: [{ id: SUBJECT }] },
      { verificationMethodKey: 'key-1', resolver },
    );
    await cred.addProofByProvider(new DefaultProvider(PRIV_HEX), { verificationMethodKey: 'key-1', resolver });
    const base = {
      type: 'DataIntegrityProof',
      cryptosuite: 'ecdsa-rdfc-2019',
      created: '2024-01-01T00:00:00Z',
      verificationMethod: `${ISSUER}#key-1`,
      proofPurpose: 'assertionMethod',
    };
    await expect(cred.addCustomProof({ ...base, proofValue: 'deadbeef' }, { resolver }))
      .rejects.toThrow(/base58btc/);
    await expect(cred.addCustomProof({ ...base, proofValue: 'zabc' }, { resolver, replaceProof: true }))
      .rejects.toThrow(/replaceProof does not apply to JSON-LD/);
    await expect(cred.addCustomProof({ ...base, proofValue: 'zabc' }, { resolver, verificationMethodKey: 'key-1' }))
      .rejects.toThrow(/cannot be applied by addCustomProof/);

    const extra = { ...base, proofValue: 'zabc', id: 'urn:proof:2', nonce: 'n1', expires: '2099-01-01T00:00:00Z' };
    await cred.addCustomProof(extra as never, { resolver });
    const set = cred.getInternalData().proof as Record<string, unknown>[];
    expect(Array.isArray(set)).toBe(true);
    expect(set).toHaveLength(2);
    expect(set[0].type).toBe('EcdsaSecp256k1Signature2019');
    expect(set[1]).toMatchObject({ id: 'urn:proof:2', nonce: 'n1', expires: '2099-01-01T00:00:00Z' });
    // Every proof must verify: the bogus second one fails the set, and pinning the first passes.
    await expect(cred.verify({ resolver })).rejects.toThrow();
    await cred.verify({ resolver, proofVerificationMethod: `${ISSUER}#key-1` }).catch(() => undefined);
  });

  it('attaches a DataIntegrityProof and verifies it', async () => {
    const resolver = new StaticResolver(buildDID());
    const cred = await JSONCredential.create(
      {
        context: ['https://www.w3.org/ns/credentials/v2'],
        id: 'urn:uuid:json',
        types: ['VerifiableCredential'],
        issuer: ISSUER,
        validFrom: new Date('2024-01-01T00:00:00Z'),
        subject: [{ id: SUBJECT, customFields: { name: 'Carol' } }],
      },
      { verificationMethodKey: 'key-1', resolver },
    );

    await cred.addProofByProvider(new DefaultProvider(PRIV_HEX), { verificationMethodKey: 'key-1', resolver });
    const out = await cred.serialize();
    expect((out as Record<string, unknown>).proof).toBeTruthy();

    const parsed = await JSONCredential.parse(JSON.stringify(out));
    await parsed.verify({ resolver });
  });
});

describe('verify with all credential options', () => {
  const SCHEMA_ID = 'https://example.test/schemas/person.json';
  const SCHEMA_JSON = {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    type: 'object',
    properties: {
      credentialSubject: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          name: { type: 'string' },
          email: { type: 'string' },
          age: { type: 'number' },
          salary: { type: 'number' },
          department: { type: 'string' },
        },
        required: ['id'],
      },
    },
    required: ['credentialSubject'],
  };

  // Real credentialStatus block from examples/my-vc.json — the test
  // resolves this URL against the live status list service so the
  // revocation path is genuinely exercised.
  const STATUS = {
    id: 'did:pila:testnet:0xedf82c5366eeffcbef566b2edffab102d140f212/credentials/status/366#965',
    type: 'BitstringStatusListEntry',
    statusPurpose: 'revocation',
    statusListIndex: '965',
    statusListCredential: STATUS_LIST_URL,
  };

  const schemaLoader = jest.fn(async (id: string) => {
    if (id !== SCHEMA_ID) throw new Error(`unexpected schema id: ${id}`);
    return new Uint8Array(Buffer.from(JSON.stringify(SCHEMA_JSON), 'utf8'));
  });

  beforeEach(() => {
    schemaLoader.mockClear();
  });

  it('verifies a JWT VC with every CredentialOptions flag set', async () => {
    const resolver = new StaticResolver(buildDID());

    const cred = await JWTCredential.create(
      {
        context: ['https://www.w3.org/ns/credentials/v2'],
        id: 'urn:uuid:full-opts-jwt',
        types: ['VerifiableCredential'],
        issuer: ISSUER,
        validFrom: new Date('2024-01-01T00:00:00Z'),
        validUntil: new Date('2099-01-01T00:00:00Z'),
        subject: [
          {
            id: SUBJECT,
            customFields: { name: 'Alice', email: 'alice@example.com' },
          },
        ],
        schemas: [{ id: SCHEMA_ID, type: 'JsonSchema' }],
        credentialStatus: [STATUS],
      },
      { verificationMethodKey: 'key-1', resolver },
    );
    await cred.addProof(PRIV_HEX);

    const token = (await cred.serialize()) as string;
    const parsed = await JWTCredential.parse(token, { resolver });

    await parsed.verify({
      validateSchema: true,
      verifyProof: true,
      checkExpiration: true,
      checkRevocation: true,
      didBaseURL: 'https://did.example.test/api/v1/did',
      verificationMethodKey: 'key-1',
      sdDisclosures: [],
      sdSelectivePaths: [],
      sdAlg: 'sha-256',
      sdShuffle: false,
      sdDecoys: [],
      schemaLoader,
      resolver,
    });

    expect(schemaLoader).toHaveBeenCalledWith(SCHEMA_ID);
  });

  it('verifies a JSON-LD VC with every CredentialOptions flag set', async () => {
    const resolver = new StaticResolver(buildDID());

    const cred = await JSONCredential.create(
      {
        context: ['https://www.w3.org/ns/credentials/v2'],
        id: 'urn:uuid:full-opts-json',
        types: ['VerifiableCredential'],
        issuer: ISSUER,
        validFrom: new Date('2024-01-01T00:00:00Z'),
        validUntil: new Date('2099-01-01T00:00:00Z'),
        subject: [
          {
            id: SUBJECT,
            // `name` is defined by the credentials/v2 context; an undefined term
            // like `email` would be dropped by the (safe-mode) JSON-LD
            // canonicalizer, so it cannot appear in a signed JSON-LD credential.
            customFields: { name: 'Bob' },
          },
        ],
        schemas: [{ id: SCHEMA_ID, type: 'JsonSchema' }],
        credentialStatus: [STATUS],
      },
      { verificationMethodKey: 'key-1', resolver },
    );
    await cred.addProofByProvider(new DefaultProvider(PRIV_HEX), { verificationMethodKey: 'key-1', resolver });

    const doc = await cred.serialize();
    const parsed = await JSONCredential.parse(JSON.stringify(doc));

    await parsed.verify({
      validateSchema: true,
      verifyProof: true,
      checkExpiration: true,
      checkRevocation: true,
      didBaseURL: 'https://did.example.test/api/v1/did',
      verificationMethodKey: 'key-1',
      sdDisclosures: [],
      sdSelectivePaths: [],
      sdAlg: 'sha-256',
      sdShuffle: false,
      sdDecoys: [],
      schemaLoader,
      resolver,
    });

    expect(schemaLoader).toHaveBeenCalledWith(SCHEMA_ID);
  });

  it('throws when credential is expired and checkExpiration=true', async () => {
    const resolver = new StaticResolver(buildDID());
    const cred = await JWTCredential.create(
      {
        context: ['https://www.w3.org/ns/credentials/v2'],
        id: 'urn:uuid:expired',
        types: ['VerifiableCredential'],
        issuer: ISSUER,
        validFrom: new Date('2000-01-01T00:00:00Z'),
        validUntil: new Date('2001-01-01T00:00:00Z'),
        subject: [{ id: SUBJECT, customFields: { name: 'Eve' } }],
      },
      { verificationMethodKey: 'key-1', resolver },
    );
    await cred.addProof(PRIV_HEX);
    const token = (await cred.serialize()) as string;
    const parsed = await JWTCredential.parse(token, { resolver });

    await expect(
      parsed.verify({
        verifyProof: true,
        checkExpiration: true,
        verificationMethodKey: 'key-1',
        resolver,
      }),
    ).rejects.toThrow(/expired/);
  });

  it('throws when schema validation fails (subject missing required field)', async () => {
    const resolver = new StaticResolver(buildDID());
    const strictSchema = {
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      type: 'object',
      properties: {
        credentialSubject: {
          type: 'object',
          properties: { id: { type: 'string' }, age: { type: 'number' } },
          required: ['id', 'age'], // age missing in the VC below
        },
      },
      required: ['credentialSubject'],
    };
    const strictLoader = async () =>
      new Uint8Array(Buffer.from(JSON.stringify(strictSchema), 'utf8'));

    const cred = await JWTCredential.create(
      {
        context: ['https://www.w3.org/ns/credentials/v2'],
        id: 'urn:uuid:badschema',
        types: ['VerifiableCredential'],
        issuer: ISSUER,
        validFrom: new Date('2024-01-01T00:00:00Z'),
        subject: [{ id: SUBJECT, customFields: { name: 'NoAge' } }],
        schemas: [{ id: SCHEMA_ID, type: 'JsonSchema' }],
      },
      { verificationMethodKey: 'key-1', resolver },
    );
    await cred.addProof(PRIV_HEX);
    const token = (await cred.serialize()) as string;
    const parsed = await JWTCredential.parse(token, { resolver });

    await expect(
      parsed.verify({
        validateSchema: true,
        verifyProof: true,
        verificationMethodKey: 'key-1',
        schemaLoader: strictLoader,
        resolver,
      }),
    ).rejects.toThrow(/validation failed/);
  });
});
