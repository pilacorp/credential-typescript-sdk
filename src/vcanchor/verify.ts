import { normalizeHash32 } from './hash';
import { proofLen, verifyProof } from './merkle';
import { HashSchemeKeccak256SortedPairsNoLeafHashV1, type Receipt } from './types';

/**
 * Checks that the receipt's vc_hash and proof fold to the anchored root, and that the
 * proof has the right length for a leaf.
 *
 * anchoredRoot and anchoredLeafCount MUST come from the anchored root record (on chain,
 * or Authen Service), never from the receipt: the receipt is the thing under test.
 * Returns false for a bad receipt; throws for bad input / caller bugs (as Go's error).
 */
export function verifyReceiptLocal(receipt: Receipt, anchoredRoot: string, anchoredLeafCount: number): boolean {
  if (receipt.hash_scheme !== HashSchemeKeccak256SortedPairsNoLeafHashV1) {
    throw new Error(`unsupported hash_scheme ${JSON.stringify(receipt.hash_scheme)}`);
  }
  const leaf = normalizeHash32(receipt.vc_hash).raw;
  const receiptRoot = normalizeHash32(receipt.root).hex;
  let anchored: { hex: string; raw: Uint8Array };
  try {
    anchored = normalizeHash32(anchoredRoot);
  } catch (e) {
    throw new Error(`invalid anchored root: ${(e as Error).message}`);
  }
  if (receiptRoot !== anchored.hex) return false;

  if (anchoredLeafCount <= 0) throw new Error('anchored leaf_count is required');
  if (receipt.leaf_count !== anchoredLeafCount) return false;
  if ((receipt.proof ?? []).length !== proofLen(anchoredLeafCount)) return false;

  const proof = (receipt.proof ?? []).map((s, i) => {
    try {
      return normalizeHash32(s).raw;
    } catch (e) {
      throw new Error(`invalid proof[${i}]: ${(e as Error).message}`);
    }
  });
  return verifyProof(leaf, proof, anchored.raw);
}
