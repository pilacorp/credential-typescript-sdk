import { AbiCoder, Interface, JsonRpcProvider, getBytes, keccak256, type InterfaceAbi } from 'ethers';
import { isHexAddress } from '../didv2/address';
import abiJson from './credential_registry_smc_abi.json';
import {
  validateVerifyByTxRequest,
  validateVerifyRequest,
  type VerifyByTxRequest,
  type VerifyRequest,
} from './model';

// The five shapes an anchoring has ever taken: three current, two legacy (still valid on chain).
const batchAnchoredEvent = 'BatchRootsAnchored';
const singleAnchoredEvent = 'TreeRootAnchored';
const issuerAnchoredEvent = 'IssuerRootsAnchored';
const legacyBatchEvent = 'BatchTreesUpdated';
const legacySingleEvent = 'TreeUpdated';

// Topic counts of a well-formed log (event id + indexed fields).
const singleAnchoredTopicCount = 3;
const issuerAnchoredTopicCount = 2;
const legacySingleTopicCount = 3;

const iface = new Interface(abiJson as InterfaceAbi);
const coder = AbiCoder.defaultAbiCoder();
const ZERO32 = `0x${'00'.repeat(32)}`;

const topicOf = (name: string): string => iface.getEvent(name)!.topicHash;
const dataTypes = (name: string): string[] =>
  iface.getEvent(name)!.inputs.filter((i) => !i.indexed).map((i) => i.type);

export class ErrNoContractAddress extends Error {
  constructor(message = 'no contract address configured') {
    super(message);
    this.name = 'ErrNoContractAddress';
  }
}
/** No receipt for the tx hash: unknown or not yet mined. */
export class ErrTxNotFound extends Error {
  constructor(message = 'transaction not found') {
    super(message);
    this.name = 'ErrTxNotFound';
  }
}
/** The tx exists but failed, so it anchored nothing. */
export class ErrTxReverted extends Error {
  constructor(message = 'transaction reverted') {
    super(message);
    this.name = 'ErrTxReverted';
  }
}
/** @deprecated only getAnchoredRoot returns it (legacy BatchTreesUpdated only). */
export class ErrRootNotAnchored extends Error {
  constructor(message = 'transaction did not anchor a root for this issuer and tree index') {
    super(message);
    this.name = 'ErrRootNotAnchored';
  }
}
/** A caller pinned verification to a contract outside the trusted set. Pins only narrow trust. */
export class ErrUntrustedContract extends Error {
  constructor(message = "contract address is not in this client's trusted set") {
    super(message);
    this.name = 'ErrUntrustedContract';
  }
}

export interface ReceiptLog {
  address: string;
  topics: readonly string[];
  data: string;
}

export interface ReceiptLike {
  /** 1 = success. Anything else (0, null) counts as reverted, like Go. */
  status?: number | bigint | null;
  logs: ReadonlyArray<ReceiptLog | null | undefined>;
}

/**
 * Reads transaction receipts. Resolve null (or throw ErrTxNotFound) when the chain has no
 * receipt; ethers' provider.getTransactionReceipt satisfies this directly.
 */
export interface ReceiptSource {
  getTransactionReceipt(txHash: string): Promise<ReceiptLike | null | undefined>;
}

/** eth_call target; ethers' JsonRpcProvider satisfies this. */
export interface CallSource {
  call(tx: { to: string; data: string }): Promise<string>;
}

export interface RegistryDeps {
  receipts?: ReceiptSource;
  caller?: CallSource;
}

const norm = (s: string): string => s.toLowerCase();
const isZeroAddress = (s: string): boolean => /^0x0{40}$/.test(norm(s));
/** Address as 0x-lowercase from any-case hex with optional prefix. */
const addr = (s: string): string => `0x${s.replace(/^0[xX]/, '').toLowerCase()}`;

function parseContractAddress(value: string): string {
  if (!isHexAddress(value)) throw new Error(`${JSON.stringify(value)} is not a 20-byte hex address`);
  const a = addr(value);
  if (isZeroAddress(a)) throw new Error('the zero address names no deployment');
  return a;
}

/** Go hexToBytes32: "0x" prefix (lowercase only) optional; exactly 32 bytes of hex. */
export function hexToBytes32(s: string): string {
  const h = s.replace(/^0x/, '');
  if (h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) throw new Error('invalid hex: encoding/hex: invalid byte');
  if (h.length / 2 !== 32) throw new Error(`length must be 32 bytes, got ${h.length / 2}`);
  return `0x${h.toLowerCase()}`;
}

export function parseProof(proof: string[]): string[] {
  return (proof ?? []).map((p, i) => {
    try {
      return hexToBytes32(p);
    } catch (e) {
      throw new Error(`proof element ${i}: ${(e as Error).message}`);
    }
  });
}

function decodeLeafAndProof(leafHex: string, proofHex: string[]): { leaf: string; proof: string[] } {
  let leaf: string;
  try {
    leaf = hexToBytes32(leafHex);
  } catch (e) {
    throw new Error(`invalid leaf: ${(e as Error).message}`);
  }
  return { leaf, proof: parseProof(proofHex) };
}

/** keccak256 of two 32-byte nodes concatenated in ascending byte order (the contract's pair hashing). */
export function hashPair(a: string, b: string): string {
  const x = getBytes(a);
  const y = getBytes(b);
  const [lo, hi] = Buffer.compare(x, y) < 0 ? [x, y] : [y, x];
  return keccak256(Buffer.concat([lo, hi]));
}

/**
 * Folds a leaf with its sibling path into the root it produces (sorted pairs, leaves not
 * hashed; empty path = the leaf itself). Fold a hash you computed from the credential: an
 * inner node folds to the root too. Inputs and output are 0x 32-byte hex.
 */
export function foldProof(leaf: string, proof: string[]): string {
  let computed = leaf.toLowerCase();
  for (const sibling of proof) computed = hashPair(computed, sibling);
  return computed;
}

/** Indexed address from a 32-byte topic: the last 20 bytes. */
const topicAddress = (topic: string): string => `0x${topic.slice(-40).toLowerCase()}`;

function pairPresent(issuers: string[], roots: string[], issuer: string, root: string): boolean {
  // Mismatched parallel arrays are not an anchoring this client can read: fail closed.
  if (issuers.length !== roots.length) return false;
  return issuers.some((a, i) => norm(a) === issuer && norm(roots[i]) === root);
}

function decodeData(event: string, data: string): any[] | null {
  try {
    return [...coder.decode(dataTypes(event), data)];
  } catch {
    return null;
  }
}

/** Whether one log records issuer anchoring root. issuer/root must be lowercase hex. */
function logAnchors(log: ReceiptLog, issuer: string, root: string): boolean {
  const t = log.topics.map(norm);
  switch (t[0]) {
    case norm(topicOf(singleAnchoredEvent)):
      return t.length === singleAnchoredTopicCount && topicAddress(t[1]) === issuer && t[2] === root;
    case norm(topicOf(batchAnchoredEvent)): {
      const d = decodeData(batchAnchoredEvent, log.data);
      return !!d && pairPresent(d[0], d[1], issuer, root);
    }
    case norm(topicOf(issuerAnchoredEvent)): {
      if (t.length !== issuerAnchoredTopicCount || topicAddress(t[1]) !== issuer) return false;
      const d = decodeData(issuerAnchoredEvent, log.data);
      return !!d && (d[0] as string[]).some((r) => norm(r) === root);
    }
    case norm(topicOf(legacySingleEvent)): {
      if (t.length !== legacySingleTopicCount || topicAddress(t[1]) !== issuer) return false;
      const d = decodeData(legacySingleEvent, log.data);
      return !!d && norm(d[0]) === root;
    }
    case norm(topicOf(legacyBatchEvent)): {
      const d = decodeData(legacyBatchEvent, log.data);
      return !!d && pairPresent(d[0], d[2], issuer, root);
    }
  }
  return false;
}

function boolWord(out: string, method: string): boolean {
  const b = getBytes(out);
  if (b.length !== 32) throw new Error(`${method} returned ${b.length} bytes, want 32`);
  // Go's ABI unpack accepts only a 0/1 word as bool.
  if (b.slice(0, 31).some((x) => x !== 0) || b[31] > 1) throw new Error(`${method}: improperly encoded boolean value`);
  return b[31] === 1;
}

/**
 * Read-only client for the Credential Registry contract: eth_call and receipt reads only,
 * no key, no gas.
 *
 * Reading a root from a log means trusting whoever emitted it, and anyone can deploy a
 * contract emitting these exact event signatures, so only logs from the trusted set
 * (contractAddress + alsoTrust) are believed. NAMING NO ADDRESS AT ALL disables that check
 * and every emitter is believed: never do that for anything that accepts outside credentials.
 *
 * contractAddress is the eth_call target for the (deprecated) view functions only; pass ""
 * if you just read logs. alsoTrust addresses are never called, only believed.
 */
export class CredentialRegistry {
  private readonly receipts: ReceiptSource | null;
  private readonly caller: CallSource | null;
  private readonly provider: JsonRpcProvider | null;
  private readonly contract: string | null;
  private readonly trusted = new Set<string>();

  constructor(rpcUrl: string, contractAddress: string, alsoTrust: string[] = [], deps: RegistryDeps = {}) {
    if (!rpcUrl) throw new Error('RPC URL is required');
    this.contract = null;
    if (contractAddress) {
      try {
        this.contract = parseContractAddress(contractAddress);
      } catch (e) {
        throw new Error(`invalid contract address: ${(e as Error).message}`);
      }
      this.trusted.add(this.contract);
    }
    alsoTrust.forEach((extra, i) => {
      try {
        this.trusted.add(parseContractAddress(extra));
      } catch (e) {
        throw new Error(`invalid contract address in alsoTrust at index ${i}: ${(e as Error).message}`);
      }
    });
    // JsonRpcProvider connects lazily, so constructing without a chain is fine.
    this.provider = deps.receipts && deps.caller ? null : new JsonRpcProvider(rpcUrl);
    this.receipts = deps.receipts ?? this.provider;
    this.caller = deps.caller ?? this.provider;
  }

  /** Empty trusted set believes every emitter (see class doc). */
  trusts(address: string): boolean {
    return this.trusted.size === 0 || this.trusted.has(addr(address));
  }

  close(): void {
    this.provider?.destroy();
  }

  private async view(method: string, args: unknown[]): Promise<string> {
    if (!this.contract || !this.caller) {
      throw new ErrNoContractAddress(
        `no contract address configured: ${method} is a call on the contract that keeps roots in storage, so its address must be passed to the constructor`,
      );
    }
    try {
      return await this.caller.call({ to: this.contract, data: iface.encodeFunctionData(method, args) });
    } catch (e) {
      throw new Error(`${method} call failed: ${(e as Error).message}`);
    }
  }

  /**
   * @deprecated The current contract has no verifyVC; use verifyVCHashByTx. Calls verifyVC
   * against the tree's CURRENT root. Throws ErrNoContractAddress without a contractAddress.
   */
  async verifyVCHashOnChain(req: VerifyRequest): Promise<boolean> {
    if (!this.contract) await this.view('verifyVC', []); // throws ErrNoContractAddress
    validateVerifyRequest(req);
    const { leaf, proof } = decodeLeafAndProof(req.leaf, req.proof);
    const out = await this.view('verifyVC', [
      addr(req.issuerAddress),
      BigInt(req.treeIndex ?? 0),
      leaf,
      proof,
    ]);
    return boolWord(out, 'verifyVC');
  }

  /**
   * Checks the proof against the root a specific tx anchored, read from its receipt logs.
   * true: the folded root was anchored for this issuer by that tx. false: the chain was asked
   * and does not attest the leaf (incl. a reverted tx). Throws when it could not be asked
   * (malformed input, RPC failure, ErrTxNotFound). req.treeIndex is ignored.
   */
  async verifyVCHashByTx(req: VerifyByTxRequest): Promise<boolean> {
    validateVerifyByTxRequest(req);
    const { leaf, proof } = decodeLeafAndProof(req.leaf, req.proof);
    let txHash: string;
    try {
      txHash = hexToBytes32(req.txHash);
    } catch (e) {
      throw new Error(`invalid tx hash: ${(e as Error).message}`);
    }
    const root = foldProof(leaf, proof);
    try {
      return req.contractAddress
        ? await this.isRootAnchoredAtContract(txHash, req.issuerAddress, root, req.contractAddress)
        : await this.isRootAnchored(txHash, req.issuerAddress, root);
    } catch (e) {
      if (e instanceof ErrTxReverted) return false;
      throw e;
    }
  }

  private async fetchReceipt(txHash: string): Promise<ReceiptLike> {
    if (!this.receipts) throw new Error('registry is not initialized');
    let receipt: ReceiptLike | null | undefined;
    try {
      receipt = await this.receipts.getTransactionReceipt(txHash);
    } catch (e) {
      if (e instanceof ErrTxNotFound) throw e;
      throw new Error(`failed to get transaction receipt: ${(e as Error).message}`);
    }
    if (receipt === null) throw new ErrTxNotFound();
    if (!receipt) throw new Error(`receipt source returned no receipt and no error for tx ${txHash}`);
    if (Number(receipt.status) !== 1) throw new ErrTxReverted();
    return receipt;
  }

  /** @deprecated Reads the legacy BatchTreesUpdated event only; throws ErrRootNotAnchored against the current contract. */
  async getAnchoredRoot(txHash: string, issuer: string, treeIndex: bigint | number): Promise<string> {
    const receipt = await this.fetchReceipt(txHash);
    const want = addr(issuer);
    const eventId = norm(topicOf(legacyBatchEvent));
    for (const log of receipt.logs) {
      if (!log || !this.trusts(log.address)) continue;
      if (!log.topics.length || norm(log.topics[0]) !== eventId) continue;
      const d = decodeData(legacyBatchEvent, log.data);
      if (!d) continue;
      const [issuers, indices, roots] = d as [string[], bigint[], string[]];
      if (issuers.length !== indices.length || issuers.length !== roots.length) continue;
      for (let i = 0; i < issuers.length; i++) {
        if (norm(issuers[i]) === want && indices[i] === BigInt(treeIndex)) return roots[i];
      }
    }
    throw new ErrRootNotAnchored();
  }

  /**
   * Whether txHash records issuer anchoring root, reading logs of every trusted contract.
   * Throws ErrTxNotFound / ErrTxReverted; a tx that merely lacks the root is false.
   */
  async isRootAnchored(txHash: string, issuer: string, root: string): Promise<boolean> {
    return this.rootAnchored(txHash, issuer, root, null);
  }

  /** isRootAnchored restricted to one deployment, which must already be trusted. */
  async isRootAnchoredAtContract(txHash: string, issuer: string, root: string, contractAddress: string): Promise<boolean> {
    if (!this.trusts(contractAddress)) throw new ErrUntrustedContract(`${new ErrUntrustedContract().message}: ${contractAddress}`);
    return this.rootAnchored(txHash, issuer, root, addr(contractAddress));
  }

  private async rootAnchored(txHash: string, issuer: string, root: string, emitter: string | null): Promise<boolean> {
    if (!this.receipts) throw new Error('registry is not initialized');
    // The contract rejects an empty root (EmptyRoot), so none was ever anchored: a verdict, not an error.
    if (norm(root) === ZERO32) return false;
    const receipt = await this.fetchReceipt(txHash);
    const issuerL = addr(issuer);
    const rootL = norm(root);
    for (const log of receipt.logs) {
      if (!log) continue; // a JSON null in "logs"
      if (emitter !== null ? addr(log.address) !== emitter : !this.trusts(log.address)) continue;
      if (!log.topics.length) continue;
      if (logAnchors(log, issuerL, rootL)) return true;
    }
    return false;
  }

  /** @deprecated The current contract has no getTreeRoot. Returns the stored root (zero = none). */
  async getTreeRoot(issuerAddress: string, treeIndex: bigint | number): Promise<string> {
    if (!this.contract) await this.view('getTreeRoot', []);
    if (!isHexAddress(issuerAddress)) throw new Error(`invalid issuer address: ${JSON.stringify(issuerAddress)}`);
    const out = await this.view('getTreeRoot', [addr(issuerAddress), BigInt(treeIndex)]);
    const b = getBytes(out);
    if (b.length !== 32) throw new Error(`unexpected getTreeRoot output length: ${b.length}`);
    return out.toLowerCase();
  }

  /** @deprecated The current contract has no treeExists. */
  async hasTree(issuerAddress: string, treeIndex: bigint | number): Promise<boolean> {
    if (!this.contract) await this.view('treeExists', []);
    if (!isHexAddress(issuerAddress)) throw new Error(`invalid issuer address: ${JSON.stringify(issuerAddress)}`);
    return boolWord(await this.view('treeExists', [addr(issuerAddress), BigInt(treeIndex)]), 'treeExists');
  }
}

export function newCredentialRegistry(rpcUrl: string, contractAddress: string, ...alsoTrust: string[]): CredentialRegistry {
  return new CredentialRegistry(rpcUrl, contractAddress, alsoTrust);
}

/** ABI event topic0 for a Registry event name (BatchRootsAnchored, TreeRootAnchored, ...). */
export function eventTopic(name: string): string {
  return topicOf(name);
}

/** Calldata for a registry view function (verifyVC, getTreeRoot, treeExists). */
export function encodeCall(method: 'verifyVC' | 'getTreeRoot' | 'treeExists', args: unknown[]): string {
  return iface.encodeFunctionData(method, args);
}

/** Encodes the data section of a non-indexed-argument event, for building logs (mirrors Go test helper). */
export function encodeEventData(name: string, args: unknown[]): string {
  return coder.encode(dataTypes(name), args);
}
