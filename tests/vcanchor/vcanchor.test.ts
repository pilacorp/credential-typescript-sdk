import {
  Batch,
  ErrBatchConflict,
  ErrBatchNotFound,
  HashSchemeKeccak256SortedPairsNoLeafHashV1,
  Manager,
  MaxLeavesPerBatch,
  MemoryStore,
  buildBatch,
  hexHash,
  mergeSorted,
  merkleProof,
  normalizeHash32,
  proofLen,
  verifyProof,
  verifyReceiptLocal,
  type Receipt,
  type Store,
} from '../../src/vcanchor';
import * as sdk from '../../src';
import vectors from '../fixtures/go-vcanchor-vccontract-vectors.json';

const ISSUER = 'did:pila:testnet:0xissuer';
const h = (n: number) => `0x${n.toString(16).padStart(64, '0')}`;
const four = [1, 2, 3, 4].map(h);
const mk = (treeId: string, hashes: string[]) => buildBatch({ issuerDID: ISSUER, externalTreeID: treeId, vcHashes: hashes });

describe('byte-exact vs Go vectors', () => {
  for (const v of vectors.batches) {
    test(`${v.kind} n=${v.n}: root, digest, every receipt`, () => {
      const b = mk('t', v.hashes);
      expect(b.root).toBe(v.root);
      expect(b.leaves_digest).toBe(v.leaves_digest);
      v.receipts.forEach((want, i) => {
        const got = b.receipt(v.hashes[i], '0xtx');
        expect(got).toEqual(want);
        expect(verifyReceiptLocal(got, v.root, v.n)).toBe(true);
      });
    });
  }
  test('receipt JSON key order/shape matches Go (omitempty tx_hash)', () => {
    const b = mk('t', four);
    expect(Object.keys(b.receipt(four[0], '0xtx'))).toEqual(Object.keys(vectors.batches[3].receipts[0]));
    expect('tx_hash' in b.receipt(four[0])).toBe(false);
  });
});

test('exposed as sdk.vcanchor namespace', () => {
  expect(sdk.vcanchor.buildBatch).toBe(buildBatch);
});

describe('buildBatch / receipts', () => {
  test('builds verifiable receipt', () => {
    const b = mk('app-tree-001', four);
    expect(b.hash_scheme).toBe(HashSchemeKeccak256SortedPairsNoLeafHashV1);
    expect(b.leaf_count).toBe(4);
    expect(b.root).toMatch(/^0x[0-9a-f]{64}$/);
    const r = b.receipt(four[2], '0xtx');
    expect(r.leaf_index).toBe(2);
    expect(r.proof).toHaveLength(2);
    expect(verifyReceiptLocal(r, b.root, 4)).toBe(true);
  });

  test('rejects tampered leaf', () => {
    const b = mk('t', four.slice(0, 3));
    const r = { ...b.receipt(four[1], '0xtx'), vc_hash: h(9) };
    expect(verifyReceiptLocal(r, b.root, 3)).toBe(false);
  });

  test('rejects duplicates (with or without 0x) and bad input', () => {
    expect(() => mk('t', [h(1), h(1).slice(2)])).toThrow(/duplicate/);
    expect(() => buildBatch({ issuerDID: '', externalTreeID: 't', vcHashes: [h(1)] })).toThrow(/issuer_did/);
    expect(() => buildBatch({ issuerDID: ISSUER, externalTreeID: '', vcHashes: [h(1)] })).toThrow(/external_tree_id/);
    expect(() => mk('t', [])).toThrow(/vc_hashes/);
    expect(() => mk('t', ['0x12'])).toThrow(/invalid 32-byte hash/);
    expect(() => mk('t', ['zz'.repeat(32)])).toThrow(/invalid/);
    expect(() => mk('t', four).receipt(h(77))).toThrow(/not in batch/);
  });

  test('normalizeHash32 trims, lowercases, drops 0x', () => {
    expect(normalizeHash32(`  0X${'AB'.repeat(32)} `.replace('0X', '0x')).hex).toBe(`0x${'ab'.repeat(32)}`);
  });

  test('proofLen matches generated proofs for 1..40 leaves', () => {
    for (let n = 1; n <= 40; n++) {
      const leaves = Array.from({ length: n }, (_, i) => normalizeHash32(h(i + 1)).raw);
      for (const idx of [0, Math.floor(n / 2), n - 1]) {
        expect(proofLen(n)).toBe(merkleProof(leaves, idx).length);
      }
    }
  });

  test('MaxLeavesPerBatch enforced', () => {
    const hashes = Array.from({ length: MaxLeavesPerBatch + 1 }, (_, i) => h(i + 1));
    expect(() => mk('over', hashes)).toThrow(/too many vc_hashes/);
    expect(mk('cap', hashes.slice(0, MaxLeavesPerBatch)).leaf_count).toBe(MaxLeavesPerBatch);
  });
});

describe('verifyReceiptLocal', () => {
  test('rejects an internal node posing as a leaf', () => {
    const b = mk('pre', four);
    const r = b.receipt(four[0], '0xtx');
    const internal = mergeSorted(normalizeHash32(r.vc_hash).raw, normalizeHash32(r.proof[0]).raw);
    const forged: Receipt = { ...r, vc_hash: hexHash(internal), proof: r.proof.slice(1) };
    // test setup guard: it really folds to the root
    expect(verifyProof(internal, forged.proof.map((s) => normalizeHash32(s).raw), normalizeHash32(r.root).raw)).toBe(true);
    for (const leaf_count of [4, 2]) {
      expect(verifyReceiptLocal({ ...forged, leaf_count }, b.root, 4)).toBe(false);
    }
  });

  test('rejects receipt without leaf_count / anchored count of 0 errors', () => {
    const r = { vc_hash: h(1), root: h(1), hash_scheme: HashSchemeKeccak256SortedPairsNoLeafHashV1 } as Receipt;
    expect(() => verifyReceiptLocal(r, r.root, 0)).toThrow(/leaf_count is required/);
    expect(verifyReceiptLocal(r, r.root, 1)).toBe(false);
  });

  test('rejects foreign tree and lying root; unsupported scheme and bad proof throw', () => {
    const anchored = mk('real', four);
    const forgedHashes = [0xf1, 0xf2, 0xf3, 0xf4].map(h);
    const forged = mk('forged', forgedHashes);
    const r = forged.receipt(forgedHashes[0], '0xtx');
    expect(verifyReceiptLocal(r, forged.root, 4)).toBe(true);
    expect(verifyReceiptLocal(r, anchored.root, 4)).toBe(false);
    expect(verifyReceiptLocal({ ...r, root: anchored.root }, anchored.root, 4)).toBe(false);
    expect(() => verifyReceiptLocal({ ...r, hash_scheme: 'x' }, forged.root, 4)).toThrow(/unsupported hash_scheme/);
    expect(() => verifyReceiptLocal({ ...r, proof: ['0x12', r.proof[1]] }, forged.root, 4)).toThrow(/invalid proof\[0\]/);
    expect(() => verifyReceiptLocal(r, 'nope', 4)).toThrow(/invalid anchored root/);
  });
});

describe('Manager + MemoryStore', () => {
  test('persists batch and generates receipt from store', async () => {
    const manager = new Manager(new MemoryStore());
    const hashes = four.slice(0, 3);
    const batch = await manager.createBatch({ issuerDID: ISSUER, externalTreeID: 'app-tree-001', vcHashes: hashes });
    await manager.validateStoredBatch(ISSUER, 'app-tree-001');
    await manager.markAnchored(ISSUER, 'app-tree-001', '0xtx');
    const r = await manager.generateReceipt(ISSUER, 'app-tree-001', hashes[1]);
    expect(r.tx_hash).toBe('0xtx');
    expect(verifyReceiptLocal(r, batch.root, 3)).toBe(true);
  });

  test('store rejects same tree with different digest, accepts a retry', async () => {
    const store = new MemoryStore();
    const first = mk('t', [h(1)]).toStoredBatch();
    await store.saveBatch(first);
    await store.saveBatch(first);
    await expect(store.saveBatch(mk('t', [h(2)]).toStoredBatch())).rejects.toBeInstanceOf(ErrBatchConflict);
  });

  test('store contract round trip', async () => {
    const store = new MemoryStore();
    const b = mk('t', [h(1), h(2)]);
    await store.saveBatch(b.toStoredBatch());
    await store.markAnchored(ISSUER, 't', '0xtx');
    const loaded = await store.getBatch(ISSUER, 't');
    expect(loaded.root).toBe(b.root);
    expect(loaded.tx_hash).toBe('0xtx');
    expect(loaded.status).toBe('anchored');
    expect(loaded.created_at_unix).toBeGreaterThan(0);
    await expect(store.getBatch(ISSUER, 'nope')).rejects.toBeInstanceOf(ErrBatchNotFound);
    await expect(store.markAnchored(ISSUER, 'nope', '0xtx')).rejects.toBeInstanceOf(ErrBatchNotFound);
  });

  test('generateReceipt requires markAnchored; empty tx hash refused', async () => {
    const manager = new Manager(new MemoryStore());
    const hashes = [h(1), h(2)];
    await manager.createBatch({ issuerDID: ISSUER, externalTreeID: 'u', vcHashes: hashes });
    await expect(manager.generateReceipt(ISSUER, 'u', hashes[0])).rejects.toThrow(/not anchored/);
    await expect(manager.markAnchored(ISSUER, 'u', '')).rejects.toThrow(/tx hash is required/);
    await manager.markAnchored(ISSUER, 'u', '0xtx');
    expect((await manager.generateReceipt(ISSUER, 'u', hashes[0])).tx_hash).toBe('0xtx');
  });

  test('store returning null becomes ErrBatchNotFound; tampered store is detected', async () => {
    const empty: Store = { saveBatch: async () => {}, getBatch: async () => null, markAnchored: async () => {} };
    await expect(new Manager(empty).markAnchored(ISSUER, 't', '0xtx')).rejects.toBeInstanceOf(ErrBatchNotFound);

    const store = new MemoryStore();
    const manager = new Manager(store);
    await manager.createBatch({ issuerDID: ISSUER, externalTreeID: 'x', vcHashes: [h(1), h(2), h(3)] });
    const tampered: Store = {
      ...store,
      saveBatch: store.saveBatch.bind(store),
      markAnchored: store.markAnchored.bind(store),
      getBatch: async (i, t) => {
        const b = await store.getBatch(i, t);
        b!.ordered_vc_hashes.reverse();
        return b;
      },
    };
    await expect(new Manager(tampered).validateStoredBatch(ISSUER, 'x')).rejects.toThrow(/root mismatch|leaves_digest mismatch/);
  });

  test('manager without a store errors', async () => {
    await expect(new Manager(null as unknown as Store).createBatch({ issuerDID: ISSUER, externalTreeID: 't', vcHashes: [h(1)] })).rejects.toThrow(/store is required/);
  });

  test('Batch is a class with a private constructor path via build', () => {
    expect(Batch.build({ issuerDID: ISSUER, externalTreeID: 't', vcHashes: [h(1)] }).root).toBe(h(1));
  });
});
