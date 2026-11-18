import type { DIDDocument, VerificationMethodEntry } from '../common/verification-method';
import type { SignerProvider } from './signer';

export const DIDTypePeople = 0;
export const DIDTypeItem = 1;
export const DIDTypeLocation = 2;
export const DIDTypeActivity = 3;

export type DIDType = 0 | 1 | 2 | 3 | number;

export const PurposeAuthentication = 'authentication';
export const PurposeAssertionMethod = 'assertionMethod';
export type VerificationPurpose = typeof PurposeAuthentication | typeof PurposeAssertionMethod;

export interface VerificationMethodSpec {
  vm: VerificationMethodEntry;
  purposes?: VerificationPurpose[];
}

export interface KeyPair {
  privateKeyHex: string;
  publicKeyHex: string;
  address: string;
  p256PublicKeyXY?: { x: string; y: string };
}

export function didTypeString(didType: DIDType): string {
  switch (didType) {
    case DIDTypeItem:
      return 'item';
    case DIDTypePeople:
      return 'people';
    case DIDTypeLocation:
      return 'location';
    case DIDTypeActivity:
      return 'activity';
    default:
      return 'unknown';
  }
}

export function toDID(method: string, address: string): string {
  return `${method}:${address}`.toLowerCase();
}

export interface DIDConfig {
  rpc: string;
  chainId: bigint;
  didSmcAddr: string;
  method: string;
  issuerSigner?: SignerProvider;
  didSigner?: SignerProvider;
  nonce: bigint;
  epoch: bigint;
  capId: string;
  syncEpoch: boolean;
  syncNonce: boolean;
  extraVMs: VerificationMethodSpec[];
  enableP256VM: boolean;
}

export type DIDOption = (cfg: DIDConfig) => void;

export interface DIDTxResult {
  did: string;
  document: DIDDocument;
  transaction: { txHex: string; txHash: string };
  secret?: { privateKeyHex: string };
}
