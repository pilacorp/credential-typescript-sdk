/**
 * End-to-end VC issuance & verification — port of vc/credential_test.go.
 * Uses a stub DID resolver so tests don't hit the network.
 */
import { secp256k1 } from '@noble/curves/secp256k1';
import { bytesToHex, hexToBytes } from '../../src/common/crypto/hex';
import {
  DIDDocument,
  ResolverProvider,
} from '../../src/common/verification-method';
import { parseCredential } from '../../src/vc/credential';
import { JWTCredential } from '../../src/vc/jwt-credential';
import { JSONCredential } from '../../src/vc/json-credential';

const PRIV_HEX = '4646464646464646464646464646464646464646464646464646464646464646';
const ISSUER = 'did:example:issuer';
const SUBJECT = 'did:example:subject';

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

  it('emits an SD-JWT when selective paths are supplied', async () => {
    const cred = await JWTCredential.create(
      {
        context: ['https://www.w3.org/ns/credentials/v2'],
        id: 'urn:uuid:sd',
        types: ['VerifiableCredential'],
        issuer: ISSUER,
        validFrom: new Date('2024-01-01T00:00:00Z'),
        subject: [{ id: SUBJECT, customFields: { name: 'Bob', secret: 's3cr3t' } }],
      },
      {
        verificationMethodKey: 'key-1',
        resolver: new StaticResolver(buildDID()),
        sdSelectivePaths: ['credentialSubject.secret'],
      },
    );
    await cred.addProof(PRIV_HEX);
    const token = (await cred.serialize()) as string;
    expect(token.includes('~')).toBe(true);

    const parsed = await JWTCredential.parse(token, {
      resolver: new StaticResolver(buildDID()),
    });
    // Reconstructed payload re-exposes the hidden claim
    expect(parsed.extractField('credentialSubject.secret')).toBe('s3cr3t');
  });
});

describe('JSONCredential.create + verify roundtrip', () => {
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

    await cred.addProof(PRIV_HEX, { verificationMethodKey: 'key-1', resolver });
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
    statusListCredential:
      'https://auth-dev.pila.vn/api/v1/issuers/did:pila:testnet:0xedf82c5366eeffcbef566b2edffab102d140f212/credentials/status/366',
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
            customFields: { name: 'Bob', email: 'bob@example.com' },
          },
        ],
        schemas: [{ id: SCHEMA_ID, type: 'JsonSchema' }],
        credentialStatus: [STATUS],
      },
      { verificationMethodKey: 'key-1', resolver },
    );
    await cred.addProof(PRIV_HEX, { verificationMethodKey: 'key-1', resolver });

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
