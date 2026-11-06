/**
 * Review gaps 5.x vs the Go SDK. Expected DocHash values were produced by Go's
 * didv2/did.DIDDocument.Hash for the same documents.
 */
import { secp256k1 } from '@noble/curves/secp256k1';
import { hexlify, toBeHex } from 'ethers';
import {
  DIDGenerator,
  WithDIDAddressSMC,
  WithIssuerSignerProvider,
  WithMethod,
  WithP256VerificationMethod,
  addressFromPublicKeyHex,
  generateDualCurveDIDKeyPair,
  generateDualCurveKeyPair,
  hashDIDDocument,
  isHexAddress,
} from '../../src/didv2';
import { DefaultProvider } from '../../src/didv2/signer';
import { HasRole, DecodeWriterAnchors, encodeWriterAnchorLog } from '../../src/didv2/didcontract';
import { buildIssueDIDPayload, signatureFromBytes } from '../../src/didv2/issuer';
import { ErrConsentInvalid, ErrChainUnavailable, errorIs, getRootConsent } from '../../src/didv2/subdid';
import { Verifier, revokedLeaf } from '../../src/didv2/subdid';
import { parseDIDDocument } from '../../src/common/verification-method';

const D = 'did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071';
const PUB = '0x03354b9ae48c3cecaf6636ba88e321847edbf450a2777a012240d6d51705de73d7';

function docWithRevoked(rev: string): Record<string, unknown> {
  return {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: D,
    controller: 'did:nda:0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a',
    verificationMethod: [
      {
        id: `${D}#key-1`,
        type: 'EcdsaSecp256k1VerificationKey2019',
        controller: D,
        publicKeyHex: PUB,
        revoked: rev,
        revocationReason: 'superseded',
      },
    ],
    authentication: [`${D}#key-1`],
    assertionMethod: [`${D}#key-1`],
    didDocumentMetadata: { type: 'people' },
  };
}

describe('5.1 revoked keeps its original RFC3339Nano text (DocHash equals Go)', () => {
  const vectors: Array<[string, string]> = [
    ['2026-01-02T10:04:05.123456789+07:00', '0x8fe18fcaad5ecc6e0d2672c157cd71e847c06f792aa8ef9e03a2fb622746324d'],
    ['2026-01-02T03:04:05.500000000Z', '0xfeaa8f7cbce2f69e922244ce1192caf6a9cecce66fff69e8577c657a227681ed'],
    ['2026-01-02T03:04:05+00:00', '0xa98cae5a4666a0448e861bf849f86db36fe1adfab4b8fde7191ea90b0786a489'],
    ['2026-01-02T03:04:05.120-05:30', '0x3270d41e888b3adfa95dd08b1838e1d9ea0be92d8f35dc8727f5af9c68f6e42b'],
  ];
  test.each(vectors)('%s', (rev, goHash) => {
    expect(hashDIDDocument(parseDIDDocument(docWithRevoked(rev)))).toBe(goHash);
  });

  test('a changed revoked Date wins over the stale text', () => {
    const doc = parseDIDDocument(docWithRevoked('2026-01-02T10:04:05.123456789+07:00'));
    doc.verificationMethod[0].revoked = new Date('2026-01-02T03:04:05.500Z');
    expect(hashDIDDocument(doc)).toBe(vectors[1][1]);
  });

  test('revoked must be a strict RFC3339 string (4.15 on parse)', () => {
    for (const bad of ['2026-01-02', '2026-01-02 03:04:05Z', '2026-02-30T00:00:00Z', 5, true]) {
      expect(() => parseDIDDocument(docWithRevoked(bad as string))).toThrow(/revoked/);
    }
  });
});

describe('5.17/5.18 JSON shape matches Go', () => {
  test('[]byte metadata is base64', () => {
    const doc = { id: D, didDocumentMetadata: { blob: new Uint8Array([1, 2, 3]) } } as never;
    expect(hashDIDDocument(doc)).toBe('0x03b23a5c1374d2157f3538ea042bac2d9a46f87c347c39961796708b822abc4a');
  });
  test('NaN/Inf and Set metadata fail like json.Marshal', () => {
    expect(() => hashDIDDocument({ id: D, didDocumentMetadata: { n: NaN } } as never)).toThrow(/unsupported/);
    expect(() => hashDIDDocument({ id: D, didDocumentMetadata: { n: Infinity } } as never)).toThrow(/unsupported/);
    expect(() => hashDIDDocument({ id: D, didDocumentMetadata: { s: new Set([1]) } } as never)).toThrow(/Set/);
  });
  test('empty JWK omitted, missing id/type/controller written as ""', () => {
    const doc = { id: D, verificationMethod: [{ publicKeyJwk: {} }] } as never;
    expect(hashDIDDocument(doc)).toBe('0x4a5627ad586159f1027d9454ed89827678198b1c94b6987763866857f989ce13');
  });
});

describe('5.2/5.3 generator config', () => {
  test('empty contract address is an error (no fallback to the default)', () => {
    expect(() => new DIDGenerator([WithDIDAddressSMC('')])).toThrow(/contract address is required/);
  });
  test('WithMethod("") is honoured for the #key-2 VM', async () => {
    const gen = new DIDGenerator([
      WithMethod(''),
      WithP256VerificationMethod(),
      WithIssuerSignerProvider(new DefaultProvider('11'.repeat(32))),
    ]);
    const res = await gen.generateDID(0, '', null);
    expect(res.did.startsWith(':0x')).toBe(true);
    expect(res.document.verificationMethod[1].id).toBe(`${res.did}#key-2`);
  });
});

describe('5.4 HasRole accepts only a 0/1 boolean word', () => {
  const word = (n: bigint) => toBeHex(n, 32);
  const caller = (out: string) => ({ call: async () => out });
  const reg = '0x75e7b09a24bce5a921babe27b62ec7bfe2230d6a';
  const role = `0x${'ab'.repeat(32)}`;
  const acct = '0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a';
  test('0 and 1', async () => {
    await expect(HasRole(caller(word(1n)), reg, role, acct)).resolves.toBe(true);
    await expect(HasRole(caller(word(0n)), reg, role, acct)).resolves.toBe(false);
  });
  test('2 and a high bit are malformed', async () => {
    await expect(HasRole(caller(word(2n)), reg, role, acct)).rejects.toThrow(/boolean/);
    await expect(HasRole(caller(word(1n << 255n)), reg, role, acct)).rejects.toThrow(/boolean/);
  });
});

describe('5.5 AddressFromPublicKeyHex checks the point', () => {
  test('rejects an off-curve 65-byte key', () => {
    const good = secp256k1.getPublicKey(new Uint8Array(32).fill(7), false);
    expect(() => addressFromPublicKeyHex(hexlify(good))).not.toThrow();
    const bad = new Uint8Array(good);
    bad[64] ^= 1;
    expect(() => addressFromPublicKeyHex(hexlify(bad))).toThrow();
  });
});

describe('5.11 signer returns v 0/1 (Go crypto.Sign)', () => {
  test('v is the recovery id and consumers still normalize to 27/28', async () => {
    const sig = await new DefaultProvider('11'.repeat(32)).sign(new Uint8Array(32).fill(3));
    expect([0, 1]).toContain(sig[64]);
    expect([27n, 28n]).toContain(signatureFromBytes(sig).v);
  });
});

describe('5.16 addresses are validated like IsHexAddress (any case, no checksum)', () => {
  const lower = '0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a';
  const upper = `0x${lower.slice(2).toUpperCase()}`; // not a valid EIP-55 checksum
  test('isHexAddress', () => {
    expect(isHexAddress(lower)).toBe(true);
    expect(isHexAddress(upper)).toBe(true);
    expect(isHexAddress(lower.slice(2))).toBe(true);
    expect(isHexAddress(`${lower}0`)).toBe(false);
    expect(isHexAddress('0xzz')).toBe(false);
  });
  test('payload builds identically for lower/upper case', () => {
    const base = { contractAddress: lower, issuerAddress: lower, didAddress: lower, didType: 0, epoch: 0n, capId: `0x${'cd'.repeat(32)}` };
    expect(buildIssueDIDPayload({ ...base, issuerAddress: upper, didAddress: upper, contractAddress: upper })).toEqual(
      buildIssueDIDPayload(base),
    );
  });
});

describe('5.19 DecodeWriterAnchors skips logs with a malformed address', () => {
  const reg = '0x75e7b09a24bce5a921babe27b62ec7bfe2230d6a';
  test('malformed log address is skipped, good logs still decode', () => {
    const good = encodeWriterAnchorLog(reg, reg, [lowerAddr], [1n], [`0x${'ee'.repeat(32)}`]);
    const anchors = DecodeWriterAnchors(
      { logs: [{ address: 'not-an-address', topics: [], data: '0x' }, null, good] },
      reg,
    );
    expect(anchors).toHaveLength(1);
  });
});
const lowerAddr = '0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a';

describe('5.21 sub-DID errors are sentinels (errors.Is)', () => {
  test('consent errors match ErrConsentInvalid', () => {
    let err: unknown;
    try {
      getRootConsent({ didDocumentMetadata: {} } as never);
    } catch (e) {
      err = e;
    }
    expect(errorIs(err, ErrConsentInvalid)).toBe(true);
    expect(errorIs(err, ErrChainUnavailable)).toBe(false);
    expect((err as Error).message).toContain('rootConsent is missing');
  });
  test('chain failures match ErrChainUnavailable', async () => {
    const v = new Verifier([
      {
        code: 'c',
        evmChainId: 1n,
        didRegistry: '0x75e7b09a24bce5a921babe27b62ec7bfe2230d6a',
        client: {
          getChainId: async () => {
            throw new Error('down');
          },
          getTransactionReceipt: async () => null,
          call: async () => '0x',
        },
      },
    ]);
    // A deactivated proof whose root is its own leaf reaches the chain check, where getChainId fails.
    const root = 'did:nda:0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a';
    const h = `0x${'11'.repeat(32)}`;
    const leaf = revokedLeaf(D.slice(D.lastIndexOf(':') + 1));
    const err = await v
      .verifySubDID({
        subDID: D,
        proof: { did: D, root_did: root, tree_index: h, chains: [{ chain: 'c', status: 'deactivated', tx_hash: h, root: leaf, path: [] }] } as never,
        chain: 'c',
      })
      .catch((e) => e);
    expect(errorIs(err, ErrChainUnavailable)).toBe(true);
    expect((err as Error).message).toContain('down');
  });
});

describe('6.14 dual-curve keygen name', () => {
  test('generateDualCurveKeyPair is canonical, old name is an alias', () => {
    expect(generateDualCurveDIDKeyPair).toBe(generateDualCurveKeyPair);
    const kp = generateDualCurveKeyPair();
    expect(kp.p256PublicKeyXY).toBeDefined();
    expect(kp.address).toBe(addressFromPublicKeyHex(kp.publicKeyHex));
  });
});
