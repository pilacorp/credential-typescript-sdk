import { concat, getAddress, keccak256 } from 'ethers';
import { hexToBytes } from '../../common/crypto/hex';

export const MaxLeaves = 8192;
const maxProofLen = 13;
const revokedLeafTag = 'revoked';

export type Hash32 = string;

export function merkleRoot(leaves: Hash32[]): Hash32 {
  checkLeafCount(leaves.length);
  let level = leaves.map(norm32);
  while (level.length > 1) level = nextLevel(level);
  return level[0];
}

export function merkleProof(leaves: Hash32[], index: number): Hash32[] {
  checkLeafCount(leaves.length);
  if (index < 0 || index >= leaves.length) {
    throw new Error(`subdid: leaf index ${index} out of range [0, ${leaves.length})`);
  }
  const proof: Hash32[] = [];
  let level = leaves.map(norm32);
  let i = index;
  while (level.length > 1) {
    const sibling = i ^ 1;
    if (sibling < level.length) proof.push(level[sibling]);
    level = nextLevel(level);
    i = Math.floor(i / 2);
  }
  return proof;
}

export function verifyProof(leaf: Hash32, path: Hash32[], root: Hash32): boolean {
  if (path.length > maxProofLen) return false;
  let h = norm32(leaf);
  for (const sibling of path) h = hashPair(h, sibling);
  return h === norm32(root);
}

export function revokedLeaf(addr: string): Hash32 {
  const a = getAddress(addr);
  return keccak256(concat([Buffer.from(revokedLeafTag, 'utf8'), Buffer.from(a.slice(2), 'hex')])).toLowerCase();
}

function checkLeafCount(n: number): void {
  if (n === 0) throw new Error('subdid: a tree needs at least one leaf');
  if (n > MaxLeaves) throw new Error(`subdid: ${n} leaves exceed the maximum of ${MaxLeaves}`);
}

function nextLevel(level: Hash32[]): Hash32[] {
  const next: Hash32[] = [];
  for (let i = 0; i + 1 < level.length; i += 2) next.push(hashPair(level[i], level[i + 1]));
  if (level.length % 2 === 1) next.push(level[level.length - 1]);
  return next;
}

function hashPair(a: Hash32, b: Hash32): Hash32 {
  let left = hexToBytes(a);
  let right = hexToBytes(b);
  if (Buffer.compare(Buffer.from(left), Buffer.from(right)) > 0) [left, right] = [right, left];
  return keccak256(concat([left, right])).toLowerCase();
}

function norm32(h: Hash32): Hash32 {
  const hex = h.startsWith('0x') ? h : `0x${h}`;
  if (hex.length !== 66) throw new Error(`hash is not 32 bytes: ${h}`);
  return hex.toLowerCase();
}
