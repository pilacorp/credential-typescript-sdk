import { Batch } from './batch';
import { ErrBatchNotFound, type Store } from './store';
import type { BatchInput, Receipt, StoredBatch } from './types';

/**
 * Builds trees, keeps them in the application's Store and proves membership. Anchoring
 * (handing a root to Authen Service) is the application's job, not the SDK's.
 */
export class Manager {
  constructor(private readonly store: Store) {}

  private requireStore(): Store {
    if (!this.store) throw new Error('store is required');
    return this.store;
  }

  async createBatch(input: BatchInput): Promise<Batch> {
    const store = this.requireStore();
    const batch = Batch.build(input);
    await store.saveBatch(batch.toStoredBatch());
    return batch;
  }

  // Store is an extension point: a (null) return -- a miss reported as success -- becomes an error here.
  private async getBatch(issuerDID: string, externalTreeID: string): Promise<StoredBatch> {
    const stored = await this.requireStore().getBatch(issuerDID, externalTreeID);
    if (!stored) {
      throw new ErrBatchNotFound(
        `vcanchor: store returned no batch for ${issuerDID}/${externalTreeID}: vcanchor: batch not found`,
      );
    }
    return stored;
  }

  /** Records the tx that anchored this batch's root, which unlocks generateReceipt. */
  async markAnchored(issuerDID: string, externalTreeID: string, txHash: string): Promise<void> {
    const store = this.requireStore();
    if (!txHash) throw new Error('tx hash is required');
    const stored = await this.getBatch(issuerDID, externalTreeID);
    await store.markAnchored(stored.issuer_did, stored.external_tree_id, txHash);
  }

  async generateReceipt(issuerDID: string, externalTreeID: string, vcHash: string): Promise<Receipt> {
    const stored = await this.getBatch(issuerDID, externalTreeID);
    if (!stored.tx_hash) throw new Error(`batch ${externalTreeID} is not anchored`);
    // ponytail: rebuilds the tree from ordered hashes (<= MaxLeavesPerBatch); persist levels if that ever hurts.
    const batch = rebuild(stored);
    ensureBatchMatchesStored(batch, stored);
    return batch.receipt(vcHash, stored.tx_hash);
  }

  async validateStoredBatch(issuerDID: string, externalTreeID: string): Promise<void> {
    const stored = await this.getBatch(issuerDID, externalTreeID);
    ensureBatchMatchesStored(rebuild(stored), stored);
  }
}

const rebuild = (s: StoredBatch): Batch =>
  Batch.build({ issuerDID: s.issuer_did, externalTreeID: s.external_tree_id, vcHashes: s.ordered_vc_hashes });

export function validateStoredBatch(stored: StoredBatch): void {
  ensureBatchMatchesStored(rebuild(stored), stored);
}

function ensureBatchMatchesStored(batch: Batch, stored: StoredBatch): void {
  if (batch.root !== stored.root) throw new Error(`stored batch root mismatch: got ${batch.root} want ${stored.root}`);
  if (batch.leaf_count !== stored.leaf_count) {
    throw new Error(`stored batch leaf_count mismatch: got ${batch.leaf_count} want ${stored.leaf_count}`);
  }
  if (batch.hash_scheme !== stored.hash_scheme) {
    throw new Error(`stored batch hash_scheme mismatch: got ${batch.hash_scheme} want ${stored.hash_scheme}`);
  }
  if (batch.leaves_digest !== stored.leaves_digest) {
    throw new Error(`stored batch leaves_digest mismatch: got ${batch.leaves_digest} want ${stored.leaves_digest}`);
  }
}
