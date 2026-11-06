import { hexHash, normalizeHash32 } from './hash';
import { digestLeaves, merkleProof, merkleRoot } from './merkle';
import {
  HashSchemeKeccak256SortedPairsNoLeafHashV1,
  MaxLeavesPerBatch,
  type BatchInput,
  type Receipt,
  type StoredBatch,
} from './types';

export class Batch {
  private constructor(
    readonly issuer_did: string,
    readonly external_tree_id: string,
    readonly root: string,
    readonly leaf_count: number,
    readonly hash_scheme: string,
    readonly leaves_digest: string,
    private readonly leavesByHash: Map<string, number>,
    private readonly leaves: Uint8Array[],
  ) {}

  static build(input: BatchInput): Batch {
    if (!input.issuerDID) throw new Error('issuer_did is required');
    if (!input.externalTreeID) throw new Error('external_tree_id is required');
    if (!input.vcHashes || input.vcHashes.length === 0) throw new Error('vc_hashes is required');
    if (input.vcHashes.length > MaxLeavesPerBatch) {
      throw new Error(`too many vc_hashes: ${input.vcHashes.length} exceeds max ${MaxLeavesPerBatch} per batch`);
    }
    const leaves: Uint8Array[] = [];
    const leavesByHash = new Map<string, number>();
    for (const hash of input.vcHashes) {
      const { hex, raw } = normalizeHash32(hash);
      if (leavesByHash.has(hex)) throw new Error(`duplicate vc_hash ${hex}`);
      leavesByHash.set(hex, leaves.length);
      leaves.push(raw);
    }
    return new Batch(
      input.issuerDID,
      input.externalTreeID,
      hexHash(merkleRoot(leaves)),
      leaves.length,
      HashSchemeKeccak256SortedPairsNoLeafHashV1,
      hexHash(digestLeaves(leaves)),
      leavesByHash,
      leaves,
    );
  }

  receipt(vcHash: string, txHash = ''): Receipt {
    const { hex } = normalizeHash32(vcHash);
    const leafIndex = this.leavesByHash.get(hex);
    if (leafIndex === undefined) throw new Error(`vc_hash ${hex} is not in batch`);
    const r: Receipt = {
      issuer_did: this.issuer_did,
      external_tree_id: this.external_tree_id,
      vc_hash: hex,
      leaf_index: leafIndex,
      leaf_count: this.leaf_count,
      root: this.root,
      proof: merkleProof(this.leaves, leafIndex).map(hexHash),
      ...(txHash ? { tx_hash: txHash } : {}),
      hash_scheme: this.hash_scheme,
    };
    return r;
  }

  /** Go batchToStoredBatch. Timestamps are left 0 for the Store to fill. */
  toStoredBatch(): StoredBatch {
    return {
      issuer_did: this.issuer_did,
      external_tree_id: this.external_tree_id,
      root: this.root,
      leaf_count: this.leaf_count,
      hash_scheme: this.hash_scheme,
      leaves_digest: this.leaves_digest,
      ordered_vc_hashes: this.leaves.map(hexHash),
      status: 'created',
      created_at_unix: 0,
      last_modified_unix: 0,
    };
  }
}

export function buildBatch(input: BatchInput): Batch {
  return Batch.build(input);
}
