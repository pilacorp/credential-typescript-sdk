import { JsonRpcProvider } from 'ethers';
import { secp256k1 } from '@noble/curves/secp256k1';
import { p256 } from '@noble/curves/nist';
import {
  DIDGenerator,
  buildDidDocument,
  buildMixedCurveDidDocument,
  generateP256KeyPair,
  createDidFromPublicKey,
  createDidFromPublicKeyWithTransaction,
  parsePublicKeyToDid,
  submitDidRegistration,
} from '../../src/did';
import { hexToBytes } from '../../src/common/crypto/hex';

describe('parsePublicKeyToDid', () => {
  it('derives the same DID from compressed and uncompressed secp256k1 keys', () => {
    const priv = hexToBytes(
      '4646464646464646464646464646464646464646464646464646464646464646',
    );
    const compressed = Buffer.from(secp256k1.getPublicKey(priv, true)).toString(
      'hex',
    );
    const uncompressed = Buffer.from(
      secp256k1.getPublicKey(priv, false),
    ).toString('hex');

    const fromCompressed = parsePublicKeyToDid(compressed);
    const fromUncompressed = parsePublicKeyToDid(uncompressed);

    expect(fromCompressed.curve).toBe('secp256k1');
    expect(fromCompressed.did).toBe(fromUncompressed.did);
    expect(fromCompressed.address).toBe(fromUncompressed.address);
  });

  it('derives the same DID from compressed and uncompressed P-256 keys', () => {
    const priv = hexToBytes(
      '1111111111111111111111111111111111111111111111111111111111111111',
    );
    const compressed = Buffer.from(p256.getPublicKey(priv, true)).toString(
      'hex',
    );
    const uncompressed = Buffer.from(p256.getPublicKey(priv, false)).toString(
      'hex',
    );

    const fromCompressed = parsePublicKeyToDid(compressed);
    const fromUncompressed = parsePublicKeyToDid(uncompressed);

    expect(fromCompressed.curve).toBe('p256');
    expect(fromCompressed.did).toBe(fromUncompressed.did);
    expect(fromCompressed.address).toBe(fromUncompressed.address);
  });

  it('falls back to hash mode for 32-byte raw keys', () => {
    const parsed = parsePublicKeyToDid(
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    );

    expect(parsed.curve).toBe('hash');
    expect(parsed.did.startsWith('did:nda:testnet:0x')).toBe(true);
  });
});

describe('DID document helpers', () => {
  it('builds a DID document with the same shape used by the Go app', () => {
    const did = 'did:nda:testnet:0x1234';
    const document = buildDidDocument('0xabcdef', did, 'people');

    expect(document['@context']).toEqual([
      'https://w3id.org/security/v1',
      'https://www.w3.org/ns/did/v1',
    ]);
    expect(document.id).toBe(did);
    expect(document.controller).toBe(did);
    expect(document.verificationMethod[0]).toEqual({
      id: `${did}#key-1`,
      type: 'EcdsaSecp256k1VerificationKey2019',
      controller: did,
      publicKeyHex: '0xabcdef',
    });
    expect(document.authentication).toEqual([`${did}#key-1`]);
    expect(document.assertionMethod).toEqual([`${did}#key-1`]);
    expect(document.didDocumentMetadata).toEqual({
      type: 'people',
      hash: '',
    });
  });

  it('uses Multikey publicKeyMultibase when the input is a P-256 public key', () => {
    const priv = hexToBytes(
      '1111111111111111111111111111111111111111111111111111111111111111',
    );
    const pub = Buffer.from(p256.getPublicKey(priv, false)).toString('hex');
    const did = 'did:nda:testnet:0xp256';
    const document = buildDidDocument(pub, did, 'people');
    expect(document.verificationMethod[0].type).toBe('Multikey');
    expect(document.verificationMethod[0].publicKeyMultibase?.startsWith('z')).toBe(true);
    expect(document.verificationMethod[0].publicKeyHex).toBeUndefined();
    expect(document['@context']).toContain('https://www.w3.org/ns/cid/v1');
  });

  it('builds a mixed-curve DID document like Go didv2', () => {
    const secpPriv = hexToBytes(
      '4646464646464646464646464646464646464646464646464646464646464646',
    );
    const secpPub = Buffer.from(secp256k1.getPublicKey(secpPriv, false)).toString('hex');
    const p256Pair = generateP256KeyPair();
    const did = 'did:nda:testnet:0xmixed';
    const document = buildMixedCurveDidDocument(secpPub, p256Pair.publicKeyHex, did, 'people');
    expect(document.verificationMethod).toHaveLength(2);
    expect(document.verificationMethod[0].type).toBe('EcdsaSecp256k1VerificationKey2019');
    expect(document.verificationMethod[1].type).toBe('Multikey');
    expect(document.verificationMethod[1].id).toBe(`${did}#key-2`);
    expect(document.authentication).toEqual([`${did}#key-1`, `${did}#key-2`]);
  });

  it('supports caller-provided DID identifiers for registration parity', () => {
    const created = createDidFromPublicKey(
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      {
        didIdentifier: 'did:nda:testnet:0xcustom',
        didType: 'people',
      },
    );

    expect(created.did).toBe('did:nda:testnet:0xcustom');
    expect(created.document.id).toBe('did:nda:testnet:0xcustom');
  });

  it('creates a registration payload with issuer_did/document/transaction', () => {
    const created = createDidFromPublicKeyWithTransaction(
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      {
        issuerDid: 'did:nda:testnet:issuer',
        didIdentifier: 'did:nda:testnet:0xholder',
        didType: 'people',
        transaction: {
          txHash: '0xhash',
          txHex: '0xhex',
        },
      },
    );

    expect(created.registration).toEqual({
      issuer_did: 'did:nda:testnet:issuer',
      document: created.document,
      transaction: {
        txHash: '0xhash',
        txHex: '0xhex',
      },
    });
  });
});

describe('submitDidRegistration', () => {
  it('posts the expected payload to /did/register', async () => {
    const fetcher = jest.fn(async () => ({
      ok: true,
      status: 200,
      text: async () => '{"ok":true}',
    })) as unknown as typeof fetch;

    const payload = createDidFromPublicKeyWithTransaction(
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      {
        issuerDid: 'did:nda:testnet:issuer',
        didIdentifier: 'did:nda:testnet:0xholder',
        transaction: { txHash: '0xhash', txHex: '0xhex' },
      },
    ).registration;

    const result = await submitDidRegistration({
      apiURL: 'https://layer2.example',
      apiKey: 'secret',
      payload,
      fetcher,
    });

    expect(fetcher).toHaveBeenCalledWith(
      'https://layer2.example/did/register',
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          'x-api-key': 'secret',
        }),
        body: JSON.stringify({
          ...payload,
          transaction: {
            TxHex: payload.transaction.txHex,
            TxHash: payload.transaction.txHash,
          },
        }),
      }),
    );
    expect(result).toEqual({ status: 200, body: '{"ok":true}' });
  });

  it('uses a custom register path when provided', async () => {
    const fetcher = jest.fn(async () => ({
      ok: true,
      status: 200,
      text: async () => '{"ok":true}',
    })) as unknown as typeof fetch;

    const payload = createDidFromPublicKeyWithTransaction(
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      {
        issuerDid: 'did:nda:testnet:issuer',
        didIdentifier: 'did:nda:testnet:0xholder',
        transaction: { txHash: '0xhash', txHex: '0xhex' },
      },
    ).registration;

    await submitDidRegistration({
      apiURL: 'https://layer2.example',
      registerPath: '/v2/did/register',
      apiKey: 'secret',
      payload,
      fetcher,
    });

    expect(fetcher).toHaveBeenCalledWith(
      'https://layer2.example/v2/did/register',
      expect.anything(),
    );
  });

  it('preserves API base paths like /api/v1 when joining the register route', async () => {
    const fetcher = jest.fn(async () => ({
      ok: true,
      status: 200,
      text: async () => '{"ok":true}',
    })) as unknown as typeof fetch;

    const payload = createDidFromPublicKeyWithTransaction(
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      {
        issuerDid: 'did:nda:testnet:issuer',
        didIdentifier: 'did:nda:testnet:0xholder',
        transaction: { txHash: '0xhash', txHex: '0xhex' },
      },
    ).registration;

    await submitDidRegistration({
      apiURL: 'https://auth-dev.pila.vn/api/v1',
      registerPath: '/did/register',
      apiKey: 'secret',
      payload,
      fetcher,
    });

    expect(fetcher).toHaveBeenCalledWith(
      'https://auth-dev.pila.vn/api/v1/did/register',
      expect.anything(),
    );
  });
});

describe('DIDGenerator', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('generates a DID, document, and signed transaction offline', async () => {
    const generator = new DIDGenerator({
      chainId: 6789,
      didAddress: '0x0000000000000000000000000000000000018888',
      method: 'did:nda',
    });

    const generated = await generator.generateDID({
      type: 'people',
      metadata: { name: 'User 1' },
    });

    expect(generated.did.startsWith('did:nda:0x')).toBe(true);
    expect(generated.secret.privateKeyHex.startsWith('0x')).toBe(true);
    expect(generated.document.id).toBe(generated.did);
    expect(generated.document.didDocumentMetadata).toEqual({
      name: 'User 1',
      type: 'people',
      hash: '',
    });
    expect(generated.transaction.txHash.startsWith('0x')).toBe(true);
    expect(generated.transaction.txHex.length).toBeGreaterThan(0);
  });

  it('re-generates a DID transaction using RPC nonce and gas price', async () => {
    jest
      .spyOn(JsonRpcProvider.prototype, 'getTransactionCount')
      .mockResolvedValue(12);
    jest.spyOn(JsonRpcProvider.prototype, 'getFeeData').mockResolvedValue({
      gasPrice: 123n,
      maxFeePerGas: null,
      maxPriorityFeePerGas: null,
      toJSON: () => ({}),
    } as any);
    jest.spyOn(JsonRpcProvider.prototype, 'estimateGas').mockResolvedValue(456n);

    const generator = new DIDGenerator({
      rpc: 'https://rpc-testnet.pila.vn',
      chainId: 6789,
      didAddress: '0x0000000000000000000000000000000000018888',
      method: 'did:nda',
    });

    const tx = await generator.reGenerateDIDTX(
      '0x4646464646464646464646464646464646464646464646464646464646464646',
      { type: 'people' },
    );

    expect(tx.txHash.startsWith('0x')).toBe(true);
    expect(tx.txHex.length).toBeGreaterThan(0);
  });
});
