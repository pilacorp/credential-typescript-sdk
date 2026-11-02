import { randomBytes } from 'node:crypto';
import { getAddress, getBytes, isAddress, keccak256, solidityPacked, hexlify, concat } from 'ethers';
import { bytesToHex } from '../common/crypto/hex';
import type { DIDType } from './types';
import type { SignerProvider } from './signer';

export const CapCreateAction = 'CAP_CREATE';
export const CapIDLength = 32;
export const DefaultEpoch = 0;

export interface IssueDIDPayload {
  contractAddress: string;
  issuerAddress: string;
  didAddress: string;
  didType: DIDType;
  capId: string;
  epoch: bigint;
}

export interface IssuerSignature {
  v: bigint;
  r: bigint;
  s: bigint;
}

export function validateIssueDIDPayload(p: IssueDIDPayload): void {
  if (!isAddress(p.contractAddress)) throw new Error(`invalid contract address: ${p.contractAddress}`);
  if (!isAddress(p.issuerAddress)) throw new Error(`invalid issuer address: ${p.issuerAddress}`);
  if (!isAddress(p.didAddress)) throw new Error(`invalid did address: ${p.didAddress}`);
  if (p.capId.length !== CapIDLength * 2 + 2) {
    throw new Error(`invalid cap id length: expected ${CapIDLength}, got ${p.capId.length}`);
  }
}

export async function generateIssueDIDSignature(
  input: IssueDIDPayload,
  issuerSigner: SignerProvider,
): Promise<IssuerSignature> {
  if (!issuerSigner) throw new Error('issuer signer is required');
  const payload = buildIssueDIDPayload(input);
  const hashPayload = keccak256(payload);
  return signPayload(Buffer.from(hashPayload.slice(2), 'hex'), issuerSigner);
}

export function buildIssueDIDPayload(input: IssueDIDPayload): Uint8Array {
  validateIssueDIDPayload(input);
  const packed = solidityPacked(
    ['string', 'address', 'address', 'uint8', 'uint64', 'bytes32'],
    [CapCreateAction, input.issuerAddress, input.didAddress, input.didType, input.epoch, input.capId],
  );
  const prefix = new Uint8Array([0x19, 0x00]);
  const addressBytes = Buffer.from(getAddress(input.contractAddress).slice(2), 'hex');
  return getBytes(concat([prefix, addressBytes, packed]));
}

export async function signPayload(payload: Uint8Array, issuerSigner: SignerProvider): Promise<IssuerSignature> {
  const sigBytes = await issuerSigner.sign(payload);
  return signatureFromBytes(sigBytes instanceof Uint8Array ? sigBytes : new Uint8Array(sigBytes));
}

export function generateCapID(): string {
  return `0x${bytesToHex(randomBytes(CapIDLength))}`;
}

export function signatureFromBytes(sig: Uint8Array): IssuerSignature {
  if (sig.length !== 65) throw new Error(`signature must be 65 bytes, got ${sig.length}`);
  let v = sig[64];
  if (v < 27) v += 27;
  const copy = new Uint8Array(sig);
  copy[64] = v;
  return {
    r: BigInt(hexlify(copy.slice(0, 32))),
    s: BigInt(hexlify(copy.slice(32, 64))),
    v: BigInt(v),
  };
}
