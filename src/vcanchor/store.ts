import type { StoredBatch } from './types';

export class ErrBatchNotFound extends Error {
  constructor(message = 'vcanchor: batch not found') {
    super(message);
    this.name = 'ErrBatchNotFound';
  }
}

export class ErrBatchConflict extends Error {
  constructor(message = 'vcanchor: batch already exists with different content') {
    super(message);
    this.name = 'ErrBatchConflict';
  }
}

export interface Store {
  saveBatch(batch: StoredBatch): Promise<void>;
  /** Resolve null/undefined or throw ErrBatchNotFound for a miss. */
  getBatch(issuerDID: string, externalTreeID: string): Promise<StoredBatch | null | undefined>;
  markAnchored(issuerDID: string, externalTreeID: string, txHash: string): Promise<void>;
}

/**
 * Whether two stored batches describe the same tree. A Store uses it in saveBatch to tell
 * a retry of the same batch (succeed) from a collision on the same key (ErrBatchConflict).
 */
export function sameBatchContent(a: StoredBatch, b: StoredBatch): boolean {
  return (
    a.issuer_did === b.issuer_did &&
    a.external_tree_id === b.external_tree_id &&
    a.root === b.root &&
    a.leaf_count === b.leaf_count &&
    a.hash_scheme === b.hash_scheme &&
    a.leaves_digest === b.leaves_digest
  );
}

const keyOf = (issuerDID: string, treeID: string) => `${issuerDID}\0${treeID}`;
const clone = (b: StoredBatch): StoredBatch => ({ ...b, ordered_vc_hashes: [...b.ordered_vc_hashes] });

/** Process-local Store (the Go test store). Use a persistent one in production. */
export class MemoryStore implements Store {
  private readonly batches = new Map<string, StoredBatch>();

  async saveBatch(batch: StoredBatch): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    const b = clone(batch);
    if (!b.created_at_unix) b.created_at_unix = now;
    b.last_modified_unix = now;
    if (!b.status) b.status = 'created';
    const key = keyOf(b.issuer_did, b.external_tree_id);
    const existing = this.batches.get(key);
    if (existing) {
      if (!sameBatchContent(existing, b)) throw new ErrBatchConflict();
      return;
    }
    this.batches.set(key, b);
  }

  async markAnchored(issuerDID: string, externalTreeID: string, txHash: string): Promise<void> {
    if (!txHash) throw new Error('tx_hash is required');
    const b = this.batches.get(keyOf(issuerDID, externalTreeID));
    if (!b) throw new ErrBatchNotFound();
    const now = Math.floor(Date.now() / 1000);
    b.tx_hash = txHash;
    b.status = 'anchored';
    b.anchored_at_unix = now;
    b.last_modified_unix = now;
  }

  async getBatch(issuerDID: string, externalTreeID: string): Promise<StoredBatch> {
    const b = this.batches.get(keyOf(issuerDID, externalTreeID));
    if (!b) throw new ErrBatchNotFound();
    return clone(b);
  }
}
