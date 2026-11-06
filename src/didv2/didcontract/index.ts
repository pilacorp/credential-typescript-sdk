import {
  Interface,
  JsonRpcProvider,
  Signature,
  Transaction,
  concat,
  getAddress,
  getBytes,
  hexlify,
  id,
  keccak256,
  toBeHex,
  zeroPadValue,
  type InterfaceAbi,
} from 'ethers';
import { isHexAddress, toEthersAddress } from '../address';
import type { SignerProvider } from '../signer';
import type { DIDType } from '../types';
import type { IssuerSignature } from '../issuer';
import artifact from './did_registry_smc_abi.json';

export const DefaultGasLimit = 200000n;
export const DocHashHexLength = 64;
export const CapIDHexLength = 64;
export const SubtreeWriterRole = keccak256(Buffer.from('SUBTREE_WRITER_ROLE'));

const WRITER_ANCHOR_EVENT = 'BatchSubtreesAnchoredByWriter';
const HAS_ROLE_METHOD = 'hasRole';

export interface ContractConfig {
  rpcUrl: string;
  contractAddress: string;
  chainId: bigint;
  gasPrice?: bigint;
  gasLimit?: bigint;
}

export interface CreateDIDRequest {
  issuerAddress: string;
  issuerSig: IssuerSignature;
  docHash: string;
  capId: string;
  didType: DIDType;
  nonce: bigint;
}

export interface SetDocumentHashRequest {
  didAddress: string;
  docHash: string;
  capId: string;
  issuerSig: IssuerSignature;
  nonce: bigint;
}

export interface SetDocumentHashByIssuerRequest {
  didAddress: string;
  docHash: string;
  nonce: bigint;
}

export interface SignedTransaction {
  txHex: string;
  txHash: string;
}

export interface WriterAnchor {
  writer: string;
  did: string;
  treeIndex: bigint;
  root: string;
}

export interface ReceiptLog {
  address: string;
  topics: readonly string[];
  data: string;
  index?: number;
}

export interface TransactionReceiptLike {
  status?: number | bigint | null;
  logs: Array<ReceiptLog | null | undefined>;
}

const abi = (artifact as { abi: InterfaceAbi }).abi;
const iface = new Interface(abi);

export function validateContractConfig(cfg: ContractConfig): void {
  if (!isHexAddress(cfg.contractAddress)) throw new Error('contract address is required');
  if (cfg.chainId <= 0n) throw new Error('chain ID must be greater than 0, it\'s required');
}

export function standardizeContractConfig(cfg: ContractConfig): ContractConfig {
  return {
    ...cfg,
    gasLimit: cfg.gasLimit && cfg.gasLimit > 0n ? cfg.gasLimit : DefaultGasLimit,
    gasPrice: cfg.gasPrice ?? 0n,
  };
}

export class Contract {
  readonly cfg: ContractConfig;
  private readonly provider: JsonRpcProvider | null;

  constructor(cfg: ContractConfig) {
    validateContractConfig(cfg);
    this.cfg = standardizeContractConfig(cfg);
    this.provider = cfg.rpcUrl ? new JsonRpcProvider(cfg.rpcUrl, Number(cfg.chainId), { staticNetwork: true }) : null;
  }

  async createDIDTx(req: CreateDIDRequest, txSigner: SignerProvider): Promise<SignedTransaction> {
    if (!txSigner) throw new Error('tx signer is required');
    if (!req) throw new Error('CreateDIDRequest is required');
    validateCreateDIDRequest(req);
    const data = iface.encodeFunctionData('createDID', [
      toEthersAddress(req.issuerAddress),
      req.didType,
      hexToBytes32(req.docHash),
      hexToBytes32(req.capId),
      Number(req.issuerSig.v),
      bytesToBytes32(bigToBytes(req.issuerSig.r)),
      bytesToBytes32(bigToBytes(req.issuerSig.s)),
    ]);
    return signLegacyTx(this.cfg, txSigner, req.nonce, data);
  }

  async setDocumentHashTx(req: SetDocumentHashRequest, txSigner: SignerProvider): Promise<SignedTransaction> {
    if (!txSigner) throw new Error('tx signer is required');
    if (!req) throw new Error('SetDocumentHashRequest is required');
    validateSetDocumentHashRequest(req);
    const data = iface.encodeFunctionData('setDocumentHash', [
      toEthersAddress(req.didAddress),
      hexToBytes32(req.docHash),
      hexToBytes32(req.capId),
      Number(req.issuerSig.v),
      bytesToBytes32(bigToBytes(req.issuerSig.r)),
      bytesToBytes32(bigToBytes(req.issuerSig.s)),
    ]);
    return signLegacyTx(this.cfg, txSigner, req.nonce, data);
  }

  async setDocumentHashByIssuerTx(
    req: SetDocumentHashByIssuerRequest,
    txSigner: SignerProvider,
  ): Promise<SignedTransaction> {
    if (!txSigner) throw new Error('tx signer is required');
    if (!req) throw new Error('SetDocumentHashByIssuerRequest is required');
    validateSetDocumentHashByIssuerRequest(req);
    const data = iface.encodeFunctionData('setDocumentHashByIssuer', [
      toEthersAddress(req.didAddress),
      hexToBytes32(req.docHash),
    ]);
    return signLegacyTx(this.cfg, txSigner, req.nonce, data);
  }

  async getCapabilityEpoch(signerAddr: string): Promise<bigint> {
    if (!signerAddr) throw new Error('signer address is required');
    if (!this.provider) throw new Error('RPC client is not initialized, please check RPC URL and try again');
    const data = iface.encodeFunctionData('getCapabilityEpoch', [toEthersAddress(signerAddr)]);
    const out = await this.provider.call({ to: this.cfg.contractAddress, data });
    const decoded = iface.decodeFunctionResult('getCapabilityEpoch', out);
    return BigInt(decoded[0]);
  }

  async getNonce(address: string): Promise<bigint> {
    if (!this.provider) throw new Error('RPC client is not initialized, please check RPC URL and try again');
    return this.provider.getTransactionCount(address, 'pending').then((n) => BigInt(n));
  }

  async hasRole(role: string, account: string): Promise<boolean> {
    if (!this.provider) throw new Error('RPC client is not initialized, please check RPC URL and try again');
    return hasRole(this.provider, this.cfg.contractAddress, role, account);
  }
}

export async function hasRole(
  caller: { call(tx: { to: string; data: string }): Promise<string> },
  registry: string,
  role: string,
  account: string,
): Promise<boolean> {
  const data = iface.encodeFunctionData(HAS_ROLE_METHOD, [role, toEthersAddress(account)]);
  const out = await caller.call({ to: toEthersAddress(registry), data });
  const bytes = getBytes(out);
  if (bytes.length !== 32) {
    throw new Error(`didcontract: ${HAS_ROLE_METHOD} returned ${bytes.length} bytes, want 32`);
  }
  // Go's ABI unpack accepts only a 0/1 word as bool; ethers would call any non-zero word true.
  if (bytes.slice(0, 31).some((b) => b !== 0) || bytes[31] > 1) {
    throw new Error(`didcontract: unpack ${HAS_ROLE_METHOD}: improperly encoded boolean value`);
  }
  return bytes[31] === 1;
}

export function decodeWriterAnchors(receipt: TransactionReceiptLike | null, registry: string): WriterAnchor[] {
  if (!receipt) throw new Error('didcontract: receipt is nil');
  if (!registry || /^(0x)?0{40}$/i.test(registry)) {
    throw new Error('didcontract: registry address is zero');
  }
  const event = iface.getEvent(WRITER_ANCHOR_EVENT);
  if (!event) throw new Error('didcontract: missing BatchSubtreesAnchoredByWriter');
  const eventId = event.topicHash;
  const registryAddr = toEthersAddress(registry);
  const anchors: WriterAnchor[] = [];
  for (const log of receipt.logs) {
    if (!log) continue;
    // A log whose address is malformed cannot be the registry's: skip it.
    if (!isHexAddress(log.address) || toEthersAddress(log.address) !== registryAddr) continue;
    if (!log.topics.length || log.topics[0] !== eventId) continue;
    anchors.push(...decodeWriterLog(log));
  }
  return anchors;
}

function decodeWriterLog(log: ReceiptLog): WriterAnchor[] {
  if (log.topics.length !== 2) {
    throw new Error(`${WRITER_ANCHOR_EVENT} has ${log.topics.length} topics, want 2`);
  }
  const parsed = iface.decodeEventLog(WRITER_ANCHOR_EVENT, log.data, log.topics);
  const dids = parsed.dids as string[];
  const treeIndexes = parsed.treeIndexes as bigint[];
  const roots = parsed.roots as string[];
  if (dids.length !== treeIndexes.length || dids.length !== roots.length) {
    throw new Error(
      `${WRITER_ANCHOR_EVENT} arrays have lengths ${dids.length}, ${treeIndexes.length} and ${roots.length}`,
    );
  }
  const writer = getAddress(`0x${log.topics[1].slice(-40)}`);
  return dids.map((did, i) => ({
    writer: writer.toLowerCase(),
    did: getAddress(did).toLowerCase(),
    treeIndex: treeIndexes[i],
    root: roots[i].toLowerCase(),
  }));
}

export function writerAnchorTopic0(): string {
  return id('BatchSubtreesAnchoredByWriter(address,address[],uint256[],bytes32[])');
}

export function encodeWriterAnchorLog(
  emitter: string,
  writer: string,
  dids: string[],
  treeIndexes: bigint[],
  roots: string[],
  index = 0,
): ReceiptLog {
  const encoded = iface.encodeEventLog(WRITER_ANCHOR_EVENT, [writer, dids, treeIndexes, roots]);
  return { address: emitter, topics: encoded.topics, data: encoded.data, index };
}

async function signLegacyTx(
  cfg: ContractConfig,
  signer: SignerProvider,
  nonce: bigint,
  data: string,
): Promise<SignedTransaction> {
  const tx = Transaction.from({
    type: 0,
    to: toEthersAddress(cfg.contractAddress),
    data,
    nonce: Number(nonce),
    gasLimit: cfg.gasLimit,
    gasPrice: cfg.gasPrice ?? 0n,
    chainId: cfg.chainId,
    value: 0n,
  });
  const digest = getBytes(tx.unsignedHash);
  const sigBytes = await signer.sign(digest);
  tx.signature = Signature.from(hexlify(sigBytes));
  const serialized = tx.serialized.startsWith('0x') ? tx.serialized.slice(2) : tx.serialized;
  return { txHex: serialized, txHash: tx.hash! };
}

function hexLen(s: string): number {
  return s.startsWith('0x') ? s.length - 2 : s.length;
}

export function validateCreateDIDRequest(r: CreateDIDRequest): void {
  if (!isHexAddress(r.issuerAddress)) throw new Error(`invalid issuer address: ${r.issuerAddress}`);
  if (!r.issuerSig || r.issuerSig.v === undefined || r.issuerSig.r === undefined || r.issuerSig.s === undefined) {
    throw new Error('issuer signature V, R, S are required');
  }
  if (hexLen(r.docHash) !== DocHashHexLength) {
    throw new Error(`invalid docHash length: expected ${DocHashHexLength} hex chars (32 bytes), got ${hexLen(r.docHash)}`);
  }
  if (hexLen(r.capId) !== CapIDHexLength) {
    throw new Error(`invalid capID length: expected ${CapIDHexLength} hex chars (32 bytes), got ${hexLen(r.capId)}`);
  }
}

export function validateSetDocumentHashRequest(r: SetDocumentHashRequest): void {
  if (!isHexAddress(r.didAddress)) throw new Error(`invalid did address: ${r.didAddress}`);
  if (!r.issuerSig || r.issuerSig.v === undefined || r.issuerSig.r === undefined || r.issuerSig.s === undefined) {
    throw new Error('issuer signature V, R, S are required');
  }
  if (hexLen(r.docHash) !== DocHashHexLength) {
    throw new Error(`invalid docHash length: expected ${DocHashHexLength} hex chars (32 bytes), got ${hexLen(r.docHash)}`);
  }
  if (hexLen(r.capId) !== CapIDHexLength) {
    throw new Error(`invalid capID length: expected ${CapIDHexLength} hex chars (32 bytes), got ${hexLen(r.capId)}`);
  }
}

export function validateSetDocumentHashByIssuerRequest(r: SetDocumentHashByIssuerRequest): void {
  if (!isHexAddress(r.didAddress)) throw new Error(`invalid did address: ${r.didAddress}`);
  if (hexLen(r.docHash) !== DocHashHexLength) {
    throw new Error(`invalid docHash length: expected ${DocHashHexLength} hex chars (32 bytes), got ${hexLen(r.docHash)}`);
  }
}

export function hexToBytes32(s: string): string {
  const hex = s.startsWith('0x') ? s.slice(2) : s;
  const b = Buffer.from(hex, 'hex');
  if (b.length !== 32) throw new Error(`length must be 32 bytes, got ${b.length}`);
  return hexlify(b);
}

function bytesToBytes32(inBytes: Uint8Array): string {
  if (inBytes.length > 32) return hexlify(inBytes.slice(inBytes.length - 32));
  return zeroPadValue(hexlify(inBytes), 32);
}

function bigToBytes(n: bigint): Uint8Array {
  const hex = n.toString(16);
  const padded = hex.length % 2 ? `0${hex}` : hex;
  return getBytes(`0x${padded}`);
}

export { iface as registryInterface, concat, toBeHex };
export { hasRole as HasRole, decodeWriterAnchors as DecodeWriterAnchors };
