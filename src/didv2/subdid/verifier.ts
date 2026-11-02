import { getAddress } from 'ethers';
import type { DIDDocument } from '../../common/verification-method';
import { DecodeWriterAnchors, HasRole, SubtreeWriterRole, type TransactionReceiptLike, type WriterAnchor } from '../didcontract';
import { checkDID, didAddress, didPrefix, docHash, validateSubDID } from './document';
import { revokedLeaf, verifyProof } from './merkle';
import type { ChainProof, ProofResponse } from './proof';
import { verifyRootConsent } from './signature';

const statusActivated = 'activated';
const statusDeactivated = 'deactivated';
const hash32Pattern = /^0x[0-9a-f]{64}$/;

export type Reason =
  | 'response_mismatch'
  | 'id_mismatch'
  | 'consent_invalid'
  | 'no_anchor'
  | 'root_mismatch'
  | 'writer_revoked'
  | 'proof_mismatch'
  | '';

export const ErrNotAnchored = new Error('subdid: the chain has not anchored this Sub-DID yet');
export const ErrDocumentRequired = new Error('subdid: an activated Sub-DID needs its document');
export const ErrChainUnavailable = new Error('subdid: the chain could not be read');
export const ErrChainMismatch = new Error('subdid: node reports another chain id');

export interface ChainClient {
  getChainId(): Promise<bigint>;
  getTransactionReceipt(hash: string): Promise<TransactionReceiptLike | null>;
  call(tx: { to: string; data: string }): Promise<string>;
}

export interface Chain {
  code: string;
  evmChainId: bigint;
  didRegistry: string;
  client: ChainClient;
}

export class Verifier {
  private readonly chains: Map<string, Chain>;

  constructor(chains: Chain[]) {
    if (!chains.length) throw new Error('subdid: a verifier needs at least one chain');
    this.chains = new Map();
    for (const c of chains) {
      if (!c.code) throw new Error('subdid: chain code is empty');
      if (c.evmChainId <= 0n) throw new Error(`subdid: chain ${c.code}: EVM chain id must be positive`);
      if (!c.didRegistry || c.didRegistry === '0x0000000000000000000000000000000000000000') {
        throw new Error(`subdid: chain ${c.code}: DID registry address is zero`);
      }
      if (!c.client) throw new Error(`subdid: chain ${c.code}: client is nil`);
      if (this.chains.has(c.code)) throw new Error(`subdid: chain ${c.code} is configured twice`);
      this.chains.set(c.code, c);
    }
  }

  async verifySubDID(req: {
    subDID: string;
    document?: DIDDocument | null;
    proof: ProofResponse | null;
    chain: string;
  }): Promise<{ status: 'invalid' | 'active' | 'revoked'; reason: Reason; chain: string; txHash?: string }> {
    if (!req.proof) throw new Error('subdid: proof is nil');
    checkDID(req.subDID);
    const c = this.chains.get(req.chain);
    if (!c) throw new Error(`subdid: chain ${JSON.stringify(req.chain)} is not configured`);
    const invalid = (reason: Reason) => ({ status: 'invalid' as const, reason, chain: c.code });
    if (!consistentProof(req.proof, req.subDID)) return invalid('response_mismatch');
    const entry = chainEntry(req.proof, c.code);
    const anchor = parseChainProof(entry);
    if (!anchor) return invalid('response_mismatch');

    let leaf: string;
    let verdict: 'active' | 'revoked' = 'active';
    switch (entry.status) {
      case statusActivated: {
        if (!req.document) throw ErrDocumentRequired;
        if (req.document.id !== req.subDID) return invalid('id_mismatch');
        try {
          validateSubDID(req.document, req.proof.root_did);
        } catch {
          return invalid('id_mismatch');
        }
        try {
          verifyRootConsent(req.document, req.proof.root_did);
        } catch {
          return invalid('consent_invalid');
        }
        leaf = docHash(req.document);
        break;
      }
      case statusDeactivated:
        leaf = revokedLeaf(didAddress(req.subDID));
        verdict = 'revoked';
        break;
      default:
        return invalid('response_mismatch');
    }

    const reason = await checkOnChain(c, req.proof, anchor, leaf);
    if (reason) return invalid(reason);
    return { status: verdict, reason: '', chain: c.code, txHash: anchor.txHash };
  }
}

function consistentProof(proof: ProofResponse, subDID: string): boolean {
  if (proof.did !== subDID) return false;
  try {
    checkDID(proof.root_did);
  } catch {
    return false;
  }
  if (didPrefix(proof.root_did) !== didPrefix(subDID) || proof.root_did === subDID) return false;
  return hash32Pattern.test(proof.tree_index) || (proof.tree_index === '' && proof.chains.length === 0);
}

function chainEntry(proof: ProofResponse, code: string): ChainProof {
  const entry = proof.chains.find((e) => e.chain === code);
  if (!entry) {
    throw new Error(`${ErrNotAnchored.message}: chain ${code}`);
  }
  return entry;
}

function parseChainProof(entry: ChainProof): { txHash: string; root: string; path: string[] } | null {
  if (!hash32Pattern.test(entry.tx_hash) || !hash32Pattern.test(entry.root)) return null;
  const path: string[] = [];
  for (const s of entry.path) {
    if (!hash32Pattern.test(s)) return null;
    path.push(s);
  }
  return { txHash: entry.tx_hash, root: entry.root, path };
}

async function checkOnChain(
  c: Chain,
  proof: ProofResponse,
  anchor: { txHash: string; root: string; path: string[] },
  leaf: string,
): Promise<Reason | ''> {
  if (!verifyProof(leaf, anchor.path, anchor.root)) return 'proof_mismatch';
  let chainId: bigint;
  try {
    chainId = await c.client.getChainId();
  } catch (e) {
    throw wrapChain(`${ErrChainUnavailable.message}: chain ${c.code}: ${(e as Error).message}`);
  }
  if (chainId !== c.evmChainId) {
    throw wrapChain(
      `${ErrChainUnavailable.message}: ${ErrChainMismatch.message}: chain ${c.code}: node reports ${chainId}, want ${c.evmChainId}`,
    );
  }
  let receipt: TransactionReceiptLike | null;
  try {
    receipt = await c.client.getTransactionReceipt(anchor.txHash);
  } catch (e) {
    throw wrapChain(`${ErrChainUnavailable.message}: chain ${c.code}: receipt ${anchor.txHash}: ${(e as Error).message}`);
  }
  if (!receipt) throw wrapChain(`${ErrChainUnavailable.message}: chain ${c.code}: receipt ${anchor.txHash} is empty`);
  if (Number(receipt.status ?? 0) !== 1) return 'no_anchor';
  const written = lastWriterAnchor(receipt, c.didRegistry, proof);
  if (!written) return 'no_anchor';
  if (written.root.toLowerCase() !== anchor.root.toLowerCase()) return 'root_mismatch';
  let isWriter: boolean;
  try {
    isWriter = await HasRole(c.client, c.didRegistry, SubtreeWriterRole, written.writer);
  } catch (e) {
    throw wrapChain(`${ErrChainUnavailable.message}: chain ${c.code}: ${(e as Error).message}`);
  }
  if (!isWriter) return 'writer_revoked';
  return '';
}

function lastWriterAnchor(
  receipt: TransactionReceiptLike,
  registry: string,
  proof: ProofResponse,
): WriterAnchor | undefined {
  let anchors: WriterAnchor[];
  try {
    anchors = DecodeWriterAnchors(receipt, registry);
  } catch {
    return undefined;
  }
  const rootAddress = getAddress(didAddress(proof.root_did)).toLowerCase();
  const treeIndex = BigInt(`0x${proof.tree_index.slice(2)}`);
  for (let i = anchors.length - 1; i >= 0; i--) {
    if (anchors[i].did === rootAddress && anchors[i].treeIndex === treeIndex) return anchors[i];
  }
  return undefined;
}

function wrapChain(message: string): Error {
  return new Error(message);
}

export { DecodeWriterAnchors as decodeWriterAnchors, HasRole as hasRole };
