/**
 * Read-only client types for verifying that a VC hash is anchored on-chain in the
 * Credential Registry contract. See registry.ts for the trust model.
 */
import { isHexAddress } from '../didv2/address';

/** Hex length of a 32-byte value without the "0x" prefix. */
export const hash32HexLen = 64;

export interface VerifyRequest {
  /** Issuer's Ethereum address (0x...). */
  issuerAddress: string;
  treeIndex?: bigint | number;
  /** VC hash (32-byte hex, "0x" optional). Compute it from the VC; never take it from the proof bundle. */
  leaf: string;
  /** Ordered sibling hashes (32-byte hex each); empty for a single-leaf tree. */
  proof: string[];
}

export interface VerifyByTxRequest {
  /** Derive from the VC's own issuer and check against issuers you trust; never from the proof bundle. */
  issuerAddress: string;
  /** @deprecated unused: the contract records (issuer, root) and no tree index. */
  treeIndex?: bigint | number;
  leaf: string;
  proof: string[];
  /** Tx that anchored the root this proof was generated against (32-byte hex, "0x" optional). */
  txHash: string;
  /** Optional: pin to one deployment from the client's trusted set (can only narrow trust). */
  contractAddress?: string;
}

/** Go validateHash32: length only ("0x" optional); hex content is checked when decoded. */
export function validateHash32(s: string): void {
  const trimmed = s.replace(/^0x/, '');
  if (trimmed.length !== hash32HexLen) {
    throw new Error(`expected ${hash32HexLen} hex chars (32 bytes), got ${trimmed.length}`);
  }
}

function validateProofFields(issuerAddress: string, leaf: string, proof: string[]): void {
  if (!isHexAddress(issuerAddress)) throw new Error(`invalid issuer address: ${JSON.stringify(issuerAddress)}`);
  try {
    validateHash32(leaf);
  } catch (e) {
    throw new Error(`invalid leaf: ${(e as Error).message}`);
  }
  (proof ?? []).forEach((p, i) => {
    try {
      validateHash32(p);
    } catch (e) {
      throw new Error(`invalid proof element at index ${i}: ${(e as Error).message}`);
    }
  });
}

export function validateVerifyRequest(r: VerifyRequest | null | undefined): void {
  if (!r) throw new Error('verify request is required');
  validateProofFields(r.issuerAddress, r.leaf, r.proof);
}

export function validateVerifyByTxRequest(r: VerifyByTxRequest | null | undefined): void {
  if (!r) throw new Error('verify request is required');
  validateProofFields(r.issuerAddress, r.leaf, r.proof);
  try {
    validateHash32(r.txHash ?? '');
  } catch (e) {
    throw new Error(`invalid tx hash: ${(e as Error).message}`);
  }
  if (r.contractAddress && !isHexAddress(r.contractAddress)) {
    throw new Error(`invalid contract address: ${JSON.stringify(r.contractAddress)}`);
  }
}
