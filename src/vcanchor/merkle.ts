import { keccak256 } from 'ethers';

const k = (...parts: Uint8Array[]): Uint8Array => Buffer.from(keccak256(Buffer.concat(parts)).slice(2), 'hex');

/** keccak256 of the pair in ascending byte order; leaves are never hashed. */
export function mergeSorted(left: Uint8Array, right: Uint8Array): Uint8Array {
  return Buffer.compare(left, right) < 0 ? k(left, right) : k(right, left);
}

function nextLevel(level: Uint8Array[]): Uint8Array[] {
  const next: Uint8Array[] = [];
  for (let i = 0; i < level.length; i += 2) {
    // An odd trailing node pairs with itself.
    next.push(mergeSorted(level[i], i + 1 < level.length ? level[i + 1] : level[i]));
  }
  return next;
}

export function merkleRoot(leaves: Uint8Array[]): Uint8Array {
  if (leaves.length === 0) throw new Error('leaves is empty');
  let level = leaves;
  while (level.length > 1) level = nextLevel(level);
  return Uint8Array.from(level[0]);
}

export function merkleProof(leaves: Uint8Array[], leafIndex: number): Uint8Array[] {
  if (leaves.length === 0) throw new Error('leaves is empty');
  if (leafIndex < 0 || leafIndex >= leaves.length) throw new Error(`leaf index ${leafIndex} out of range`);
  const proof: Uint8Array[] = [];
  let index = leafIndex;
  let level = leaves;
  while (level.length > 1) {
    let sibling = index ^ 1;
    if (sibling >= level.length) sibling = index;
    proof.push(Uint8Array.from(level[sibling]));
    index = Math.floor(index / 2);
    level = nextLevel(level);
  }
  return proof;
}

export function verifyProof(leaf: Uint8Array, proof: Uint8Array[], root: Uint8Array): boolean {
  let current: Uint8Array = Uint8Array.from(leaf);
  for (const sibling of proof) current = mergeSorted(current, sibling);
  return Buffer.compare(current, root) === 0;
}

/** keccak256 over the concatenation of all leaves. */
export function digestLeaves(leaves: Uint8Array[]): Uint8Array {
  return k(...leaves);
}

/**
 * Siblings in a leaf's proof for a tree of leafCount leaves: ceil(log2(leafCount)).
 * It is what separates a leaf from an internal node, whose proof is strictly shorter.
 */
export function proofLen(leafCount: number): number {
  return leafCount <= 1 ? 0 : (leafCount - 1).toString(2).length;
}
