export const HashSchemeKeccak256SortedPairsNoLeafHashV1 = 'keccak256-sorted-pairs-no-leaf-hash-v1';

/**
 * Caps how many VC hashes one batch (one Merkle root) may hold. Authen Service enforces
 * the same cap on a submitted root (EXTERNAL_MERKLE_MAX_LEAF_COUNT, default 10000), so
 * raising it here alone only moves the rejection from buildBatch to submit time.
 */
export const MaxLeavesPerBatch = 10000;

export interface BatchInput {
  issuerDID: string;
  externalTreeID: string;
  vcHashes: string[];
}

// Field names of Batch/Receipt/StoredBatch are snake_case: they are the Go JSON wire format.
export interface Receipt {
  issuer_did: string;
  external_tree_id: string;
  vc_hash: string;
  leaf_index: number;
  leaf_count: number;
  root: string;
  proof: string[];
  tx_hash?: string;
  hash_scheme: string;
}

export interface StoredBatch {
  issuer_did: string;
  external_tree_id: string;
  root: string;
  leaf_count: number;
  hash_scheme: string;
  leaves_digest: string;
  ordered_vc_hashes: string[];
  tx_hash?: string;
  /** Local lifecycle state: "created" when first handed to the Store, then what MarkAnchored writes. */
  status: string;
  anchored_at_unix?: number;
  created_at_unix: number;
  last_modified_unix: number;
}
