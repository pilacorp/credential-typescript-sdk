import { getAddress } from 'ethers';
import * as sdk from '../../src';
import {
  CredentialRegistry,
  ErrNoContractAddress,
  ErrRootNotAnchored,
  ErrTxNotFound,
  ErrTxReverted,
  ErrUntrustedContract,
  encodeCall,
  encodeEventData,
  eventTopic,
  foldProof,
  hashPair,
  hexToBytes32,
  parseProof,
  validateVerifyByTxRequest,
  validateVerifyRequest,
  type ReceiptLike,
  type ReceiptLog,
  type VerifyByTxRequest,
} from '../../src/vccontract';
import vectors from '../fixtures/go-vcanchor-vccontract-vectors.json';

const mkLeaf = (b: number) => `0x${b.toString(16).padStart(2, '0').repeat(32)}`;
const REGISTRY = '0x1111111111111111111111111111111111111111';
const LEGACY = '0x2222222222222222222222222222222222222222';
const ATTACKER = '0xdead00000000000000000000000000000000beef';
const ISSUER = '0xabc0000000000000000000000000000000000001';
const OTHER = '0xabc0000000000000000000000000000000000002';
const LAZY_RPC = 'http://127.0.0.1:1';
const pad = (a: string) => `0x${a.slice(2).toLowerCase().padStart(64, '0')}`;

const ok = (...logs: Array<ReceiptLog | null>): ReceiptLike => ({ status: 1, logs: logs });
const stub = (receipt: ReceiptLike | null | undefined, err?: Error) => ({
  getTransactionReceipt: async () => {
    if (err) throw err;
    return receipt;
  },
});
function registry(source: ReturnType<typeof stub>, ...also: string[]) {
  return new CredentialRegistry(LAZY_RPC, REGISTRY, also, { receipts: source, caller: { call: async () => '0x' } });
}

const batchLog = (emitter: string, issuers: string[], roots: string[]): ReceiptLog => ({
  address: emitter,
  topics: [eventTopic('BatchRootsAnchored')],
  data: encodeEventData('BatchRootsAnchored', [issuers, roots]),
});
const singleLog = (emitter: string, issuer: string, root: string): ReceiptLog => ({
  address: emitter,
  topics: [eventTopic('TreeRootAnchored'), pad(issuer), root],
  data: '0x',
});
const issuerBatchLog = (emitter: string, issuer: string, roots: string[]): ReceiptLog => ({
  address: emitter,
  topics: [eventTopic('IssuerRootsAnchored'), pad(issuer)],
  data: encodeEventData('IssuerRootsAnchored', [roots]),
});
const legacyBatchLog = (emitter: string, issuers: string[], roots: string[]): ReceiptLog => ({
  address: emitter,
  topics: [eventTopic('BatchTreesUpdated')],
  data: encodeEventData('BatchTreesUpdated', [issuers, roots.map((_, i) => 7 + i), roots]),
});
const legacySingleLog = (emitter: string, issuer: string, root: string): ReceiptLog => ({
  address: emitter,
  topics: [eventTopic('TreeUpdated'), pad(issuer), pad('0x07')],
  data: encodeEventData('TreeUpdated', [root]),
});

function everyShape(emitter: string, issuer: string, root: string): Array<[string, ReceiptLog]> {
  return [
    ['current single', singleLog(emitter, issuer, root)],
    ['current cross-issuer batch', batchLog(emitter, [OTHER, issuer], [mkLeaf(1), root])],
    ['current issuer batch', issuerBatchLog(emitter, issuer, [mkLeaf(2), root])],
    ['legacy single', legacySingleLog(emitter, issuer, root)],
    ['legacy batch', legacyBatchLog(emitter, [OTHER, issuer], [mkLeaf(3), root])],
  ];
}

const anchored = (r: CredentialRegistry, root: string) => r.isRootAnchored(mkLeaf(0), ISSUER, root);

describe('byte-exact vs Go vectors', () => {
  test('event topics', () => {
    for (const [name, topic] of Object.entries(vectors.topics)) expect(eventTopic(name)).toBe(topic);
  });
  test('calldata', () => {
    const { fold, calldata } = vectors;
    expect(encodeCall('verifyVC', [ISSUER, 5n, fold.leaf, fold.proof])).toBe(calldata.verifyVC);
    expect(encodeCall('verifyVC', [ISSUER, 0n, fold.leaf, []])).toBe(calldata.verifyVCEmpty);
    expect(encodeCall('getTreeRoot', [ISSUER, 7n])).toBe(calldata.getTreeRoot);
    expect(encodeCall('treeExists', [ISSUER, 7n])).toBe(calldata.treeExists);
  });
  test('event data encoding', () => {
    const { fold, logdata } = vectors;
    const [leaf, sib] = [fold.leaf, fold.proof[0]];
    expect(encodeEventData('BatchRootsAnchored', [[OTHER, ISSUER], [sib, leaf]])).toBe(logdata.batch);
    expect(encodeEventData('IssuerRootsAnchored', [[sib, leaf]])).toBe(logdata.issuer);
    expect(encodeEventData('TreeUpdated', [leaf])).toBe(logdata.legacySingle);
    expect(encodeEventData('BatchTreesUpdated', [[OTHER, ISSUER], [7, 8], [sib, leaf]])).toBe(logdata.legacyBatch);
  });
  test('foldProof', () => {
    const { fold } = vectors;
    expect(foldProof(fold.leaf, fold.proof)).toBe(fold.folded);
    expect(foldProof(fold.leaf, fold.proof.slice(0, 1))).toBe(fold.folded1);
  });
  test('foldProof agrees with the vcanchor tree for every Go receipt', () => {
    for (const v of vectors.batches) for (const r of v.receipts) expect(foldProof(r.vc_hash, r.proof)).toBe(r.root);
  });
  test('exposed as sdk.vccontract namespace', () => {
    expect(sdk.vccontract.foldProof).toBe(foldProof);
  });
});

describe('helpers and validation', () => {
  test('hexToBytes32 / parseProof', () => {
    expect(hexToBytes32(mkLeaf(0xcd))).toBe(mkLeaf(0xcd));
    expect(() => hexToBytes32('0x1234')).toThrow();
    expect(parseProof([mkLeaf(1), mkLeaf(2)])).toEqual([mkLeaf(1), mkLeaf(2)]);
    expect(() => parseProof(['0xzz'])).toThrow(/proof element 0/);
  });

  test('VerifyRequest.Validate', () => {
    const valid = { issuerAddress: ISSUER, treeIndex: 0, leaf: mkLeaf(1), proof: [mkLeaf(2)] };
    expect(() => validateVerifyRequest(valid)).not.toThrow();
    expect(() => validateVerifyRequest({ ...valid, issuerAddress: 'not-an-address' })).toThrow(/invalid issuer address/);
    expect(() => validateVerifyRequest({ ...valid, leaf: '0xabcd' })).toThrow(/invalid leaf/);
    expect(() => validateVerifyRequest(null)).toThrow(/required/);
  });

  test('VerifyByTxRequest.Validate', () => {
    const valid: VerifyByTxRequest = { issuerAddress: ISSUER, leaf: mkLeaf(1), proof: [mkLeaf(2)], txHash: mkLeaf(3) };
    expect(() => validateVerifyByTxRequest(valid)).not.toThrow();
    expect(() => validateVerifyByTxRequest({ ...valid, issuerAddress: 'x' })).toThrow();
    expect(() => validateVerifyByTxRequest({ ...valid, txHash: '0xabcd' })).toThrow(/invalid tx hash/);
    expect(() => validateVerifyByTxRequest({ ...valid, txHash: '' })).toThrow(/invalid tx hash/);
    expect(() => validateVerifyByTxRequest({ ...valid, contractAddress: 'bad' })).toThrow(/invalid contract address/);
  });

  test('merkle fold: 4-leaf tree, tampering, single leaf, inner node folds too', () => {
    const [a, b, c, d] = [0x0a, 0x0b, 0x0c, 0x0d].map(mkLeaf);
    const ab = hashPair(a, b);
    const cd = hashPair(c, d);
    const root = hashPair(ab, cd);
    expect(foldProof(a, [b, cd])).toBe(root);
    expect(foldProof(c, [d, ab])).toBe(root);
    expect(foldProof(a, [mkLeaf(0xff), cd])).not.toBe(root);
    expect(foldProof(mkLeaf(0xee), [b, cd])).not.toBe(root);
    expect(foldProof(mkLeaf(0x42), [])).toBe(mkLeaf(0x42));
    expect(hashPair(a, b)).toBe(hashPair(b, a));
    expect(hashPair(a, b)).toBe(`0x0d0f9871649057367c9802ed72c3863f53b2d28ae3d10ece2d4ef0d2f9213784`);
    expect(root).toBe(`0x94d1872730575cc36cfe8dc134c661933532c76cacf4512666feeb402206ca29`);
    expect(foldProof(ab, [cd])).toBe(root); // inner node reaches the root as well
  });
});

describe('construction and trust', () => {
  test('accepts no contract address, trusts alsoTrust', async () => {
    const r = new CredentialRegistry(LAZY_RPC, '', [REGISTRY, LEGACY]);
    expect(r.trusts(REGISTRY) && r.trusts(LEGACY)).toBe(true);
    expect(r.trusts(ATTACKER)).toBe(false);
    await expect(r.getTreeRoot(ISSUER, 1)).rejects.toBeInstanceOf(ErrNoContractAddress);
    await expect(r.hasTree(ISSUER, 1)).rejects.toBeInstanceOf(ErrNoContractAddress);
    await expect(
      r.verifyVCHashOnChain({ issuerAddress: ISSUER, leaf: mkLeaf(1), proof: [mkLeaf(2)] }),
    ).rejects.toBeInstanceOf(ErrNoContractAddress);
    r.close();
  });

  test('empty trusted set believes any emitter (documented cost); one address rejects the forgery', async () => {
    const forged = mkLeaf(0xf0);
    const log = singleLog(ATTACKER, ISSUER, forged);
    const open = new CredentialRegistry(LAZY_RPC, '', [], { receipts: stub(ok(log)) });
    expect(open.trusts(ATTACKER)).toBe(true);
    expect(await anchored(open, forged)).toBe(true);
    expect(await anchored(registry(stub(ok(log))), forged)).toBe(false);
  });

  test('log-only client with no call target still reads logs', async () => {
    const want = mkLeaf(0xbb);
    const r = new CredentialRegistry(LAZY_RPC, '', [REGISTRY], {
      receipts: stub(ok(batchLog(REGISTRY, [ISSUER], [want]))),
    });
    expect(await anchored(r, want)).toBe(true);
  });

  test('zero address / malformed address / missing rpc refused', () => {
    const zero = `0x${'0'.repeat(40)}`;
    expect(() => new CredentialRegistry(LAZY_RPC, zero)).toThrow(/zero address/);
    expect(() => new CredentialRegistry(LAZY_RPC, zero, [REGISTRY])).toThrow();
    expect(() => new CredentialRegistry(LAZY_RPC, REGISTRY, [zero])).toThrow();
    expect(() => new CredentialRegistry(LAZY_RPC, REGISTRY, [LEGACY, zero])).toThrow();
    expect(() => new CredentialRegistry(LAZY_RPC, '0xnope')).toThrow(/invalid contract address/);
    expect(() => new CredentialRegistry(LAZY_RPC, REGISTRY, [LEGACY, '0xnope'])).toThrow(/index 1/);
    expect(() => new CredentialRegistry('', REGISTRY)).toThrow(/RPC URL is required/);
  });

  test('trust comparison ignores address case / checksum', async () => {
    const want = mkLeaf(0xbb);
    const r = registry(stub(ok(batchLog(getAddress(REGISTRY), [ISSUER], [want]))));
    expect(await anchored(r, want)).toBe(true);
  });
});

describe('isRootAnchored log rules', () => {
  const want = mkLeaf(0xbb);

  test.each(everyShape(REGISTRY, ISSUER, want))('reads %s', async (_n, log) => {
    expect(await anchored(registry(stub(ok(log))), want)).toBe(true);
  });
  test.each(everyShape(REGISTRY, ISSUER, want))('rejects absent root: %s', async (_n, log) => {
    expect(await anchored(registry(stub(ok(log))), mkLeaf(0xcc))).toBe(false);
  });
  test.each(everyShape(REGISTRY, OTHER, want))('rejects another issuer: %s', async (_n, log) => {
    expect(await anchored(registry(stub(ok(log))), want)).toBe(false);
  });
  test.each(everyShape(ATTACKER, ISSUER, want))('rejects foreign emitter: %s', async (_n, log) => {
    expect(await anchored(registry(stub(ok(log))), want)).toBe(false);
  });

  test('trusts every configured contract and reads mixed logs', async () => {
    const r = registry(
      stub(ok(legacyBatchLog(LEGACY, [OTHER], [mkLeaf(1)]), batchLog(REGISTRY, [ISSUER], [want]))),
      LEGACY,
    );
    expect(await anchored(r, want)).toBe(true);
  });

  test('pinning narrows, never widens', async () => {
    const r = registry(stub(ok(legacyBatchLog(LEGACY, [ISSUER], [want]))), LEGACY);
    expect(await r.isRootAnchoredAtContract(mkLeaf(0), ISSUER, want, LEGACY)).toBe(true);
    expect(await r.isRootAnchoredAtContract(mkLeaf(0), ISSUER, want, REGISTRY)).toBe(false);
    await expect(r.isRootAnchoredAtContract(mkLeaf(0), ISSUER, want, ATTACKER)).rejects.toBeInstanceOf(
      ErrUntrustedContract,
    );
  });

  test('topicless log, truncated topics, nil logs', async () => {
    expect(await anchored(registry(stub(ok({ address: REGISTRY, topics: [], data: '0x' }))), want)).toBe(false);
    for (const ev of ['TreeRootAnchored', 'IssuerRootsAnchored', 'TreeUpdated']) {
      const log = { address: REGISTRY, topics: [eventTopic(ev)], data: '0x' };
      expect(await anchored(registry(stub(ok(log))), want)).toBe(false);
    }
    expect(await anchored(registry(stub(ok(null))), want)).toBe(false);
  });

  test('receipt outcomes', async () => {
    await expect(anchored(registry(stub(null)), want)).rejects.toBeInstanceOf(ErrTxNotFound);
    await expect(anchored(registry(stub(null, new ErrTxNotFound())), want)).rejects.toBeInstanceOf(ErrTxNotFound);
    await expect(anchored(registry(stub({ status: 0, logs: [] })), want)).rejects.toBeInstanceOf(ErrTxReverted);
    await expect(anchored(registry(stub(undefined)), want)).rejects.toThrow(/returned no receipt/);
    await expect(anchored(registry(stub(null, new Error('boom'))), want)).rejects.toThrow(/failed to get transaction receipt: boom/);
  });

  test('missing receipt source', async () => {
    const r = new CredentialRegistry(LAZY_RPC, REGISTRY, [], { receipts: undefined, caller: { call: async () => '0x' } });
    (r as unknown as { receipts: null }).receipts = null;
    await expect(anchored(r, want)).rejects.toThrow(/not initialized/);
  });

  test('mismatched parallel arrays fail closed', async () => {
    const bad = (ev: string, args: unknown[]): ReceiptLog => ({ address: REGISTRY, topics: [eventTopic(ev)], data: encodeEventData(ev, args) as string });
    const logs = [
      bad('BatchRootsAnchored', [[ISSUER, OTHER], [want]]),
      bad('BatchTreesUpdated', [[ISSUER, OTHER], [7], [want]]),
    ];
    for (const log of logs) expect(await anchored(registry(stub(ok(log))), want)).toBe(false);
  });

  test('undecodable data is skipped, not thrown', async () => {
    const log = { address: REGISTRY, topics: [eventTopic('BatchRootsAnchored')], data: '0x1234' };
    expect(await anchored(registry(stub(ok(log))), want)).toBe(false);
  });

  test('empty root is a verdict and skips the receipt lookup', async () => {
    const r = registry(stub(null, new Error('receipt source must not be called')));
    expect(await anchored(r, `0x${'00'.repeat(32)}`)).toBe(false);
  });
});

describe('getAnchoredRoot (deprecated)', () => {
  const want = mkLeaf(0xbb);
  test('serves legacy anchorings by issuer and tree index', async () => {
    const r = registry(stub(ok(legacyBatchLog(REGISTRY, [OTHER, ISSUER], [mkLeaf(1), want]))));
    expect(await r.getAnchoredRoot(mkLeaf(0), ISSUER, 8)).toBe(want);
  });
  test('finds nothing in current events or nil logs', async () => {
    for (const [, log] of [
      ['s', singleLog(REGISTRY, ISSUER, want)],
      ['b', batchLog(REGISTRY, [ISSUER], [want])],
      ['i', issuerBatchLog(REGISTRY, ISSUER, [want])],
    ] as Array<[string, ReceiptLog]>) {
      await expect(registry(stub(ok(log))).getAnchoredRoot(mkLeaf(0), ISSUER, 7)).rejects.toBeInstanceOf(ErrRootNotAnchored);
    }
    await expect(registry(stub(ok(null))).getAnchoredRoot(mkLeaf(0), ISSUER, 7)).rejects.toBeInstanceOf(ErrRootNotAnchored);
  });
});

describe('verifyVCHashByTx', () => {
  const leaf = mkLeaf(0xa1);
  const sibling = mkLeaf(0xb2);
  const root = hashPair(leaf, sibling);
  const txHash = mkLeaf(0xcd);
  const req = (over: Partial<VerifyByTxRequest> = {}): VerifyByTxRequest => ({
    issuerAddress: ISSUER, leaf, proof: [sibling], txHash, ...over,
  });
  const standard = () => ok(batchLog(REGISTRY, [ISSUER], [root]));

  const cases: Array<[string, () => ReturnType<typeof stub>, string[], Partial<VerifyByTxRequest>, boolean | 'untrusted' | 'notfound']> = [
    ['the leaf this transaction anchored', () => stub(standard()), [], {}, true],
    ['a proof that folds to something else', () => stub(standard()), [], { proof: [mkLeaf(0xee)] }, false],
    ['a leaf that is not in the tree', () => stub(standard()), [], { leaf: mkLeaf(0xef) }, false],
    ['a different issuer', () => stub(standard()), [], { issuerAddress: OTHER }, false],
    ['reverted tx is a verdict', () => stub({ status: 0, logs: [] }), [], {}, false],
    ['unmined tx is a failure', () => stub(null), [], {}, 'notfound'],
    ['previous contract single event', () => stub(ok(legacySingleLog(LEGACY, ISSUER, root))), [LEGACY], {}, true],
    ['previous contract batch event', () => stub(ok(legacyBatchLog(LEGACY, [OTHER, ISSUER], [mkLeaf(1), root]))), [LEGACY], {}, true],
    ['pinned to the emitting deployment', () => stub(ok(batchLog(LEGACY, [ISSUER], [root]))), [LEGACY], { contractAddress: LEGACY }, true],
    ['pinned to another trusted deployment', () => stub(standard()), [LEGACY], { contractAddress: LEGACY }, false],
    ['pinned outside the trusted set', () => stub(standard()), [], { contractAddress: ATTACKER }, 'untrusted'],
  ];
  test.each(cases)('%s', async (_n, source, also, over, want) => {
    const r = registry(source(), ...also);
    if (want === 'untrusted') await expect(r.verifyVCHashByTx(req(over))).rejects.toBeInstanceOf(ErrUntrustedContract);
    else if (want === 'notfound') await expect(r.verifyVCHashByTx(req(over))).rejects.toBeInstanceOf(ErrTxNotFound);
    else expect(await r.verifyVCHashByTx(req(over))).toBe(want);
  });

  test('malformed request throws', async () => {
    await expect(registry(stub(standard())).verifyVCHashByTx(req({ issuerAddress: 'not-an-address' }))).rejects.toThrow();
    await expect(registry(stub(standard())).verifyVCHashByTx(req({ leaf: `0x${'zz'.repeat(32)}` }))).rejects.toThrow(/invalid leaf/);
  });
});

describe('view functions via injected caller', () => {
  const calls: Array<{ to: string; data: string }> = [];
  const word = (n: number) => `0x${n.toString(16).padStart(64, '0')}`;
  const withCaller = (out: string) =>
    new CredentialRegistry(LAZY_RPC, REGISTRY, [], {
      receipts: stub(null),
      caller: { call: async (tx) => (calls.push(tx), out) },
    });

  test('verifyVCHashOnChain sends Go-identical calldata and decodes the bool', async () => {
    const { fold, calldata } = vectors;
    const r = withCaller(word(1));
    expect(await r.verifyVCHashOnChain({ issuerAddress: ISSUER, treeIndex: 5, leaf: fold.leaf, proof: fold.proof })).toBe(true);
    expect(calls.at(-1)).toEqual({ to: REGISTRY, data: calldata.verifyVC });
    expect(await withCaller(word(0)).verifyVCHashOnChain({ issuerAddress: ISSUER, leaf: fold.leaf, proof: [] })).toBe(false);
    await expect(withCaller(word(2)).verifyVCHashOnChain({ issuerAddress: ISSUER, leaf: fold.leaf, proof: [] })).rejects.toThrow(/improperly encoded boolean/);
    await expect(withCaller('0x').verifyVCHashOnChain({ issuerAddress: ISSUER, leaf: fold.leaf, proof: [] })).rejects.toThrow(/want 32/);
  });

  test('getTreeRoot / hasTree', async () => {
    const root = mkLeaf(0x77);
    expect(await withCaller(root).getTreeRoot(ISSUER, 7)).toBe(root);
    expect(calls.at(-1)!.data).toBe(vectors.calldata.getTreeRoot);
    expect(await withCaller(word(1)).hasTree(ISSUER, 7)).toBe(true);
    expect(calls.at(-1)!.data).toBe(vectors.calldata.treeExists);
    await expect(withCaller(root).getTreeRoot('bad', 7)).rejects.toThrow(/invalid issuer address/);
  });

  test('call failure is wrapped', async () => {
    const r = new CredentialRegistry(LAZY_RPC, REGISTRY, [], {
      receipts: stub(null),
      caller: { call: async () => { throw new Error('rpc down'); } },
    });
    await expect(r.hasTree(ISSUER, 1)).rejects.toThrow(/treeExists call failed: rpc down/);
  });
});
