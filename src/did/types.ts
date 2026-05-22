import type { DIDDocument } from '../common/verification-method';

export type DidCurve = 'secp256k1' | 'p256' | 'hash';
export type DIDType = 'item' | 'people' | 'location' | 'default';

export interface SubmitDidTx {
  txHash: string;
  txHex: string;
}

export interface DidRegistrationPayload {
  issuer_did: string;
  document: DIDDocument;
  transaction: SubmitDidTx;
}

export interface ParsedDidPublicKey {
  curve: DidCurve;
  address: string;
  did: string;
  publicKeyHex: string;
}

export interface CreateDidFromPublicKeyOptions {
  didType?: string;
  didMethod?: string;
  didIdentifier?: string;
}

export interface CreatedDidFromPublicKey extends ParsedDidPublicKey {
  document: DIDDocument;
}

export interface CreateDidRegistrationPayloadOptions
  extends CreateDidFromPublicKeyOptions {
  issuerDid: string;
  transaction: SubmitDidTx;
}

export interface CreateDidFromPublicKeyWithTransactionOptions
  extends CreateDidRegistrationPayloadOptions {}

export interface CreatedDidRegistration {
  did: string;
  curve: DidCurve;
  address: string;
  document: DIDDocument;
  registration: DidRegistrationPayload;
}

export interface SubmitDidRegistrationOptions {
  apiURL: string;
  apiKey: string;
  payload: DidRegistrationPayload;
  fetcher?: typeof fetch;
  signal?: AbortSignal;
}

export interface SubmitDidRegistrationResult {
  status: number;
  body: string;
}

export interface DIDGeneratorConfig {
  rpc?: string;
  chainId?: number;
  didAddress?: string;
  method?: string;
}

export interface CreateDID {
  type: DIDType;
  metadata?: Record<string, unknown>;
  hash?: string;
}

export interface Secret {
  privateKeyHex: string;
}

export interface GeneratedDID {
  did: string;
  secret: Secret;
  document: DIDDocument;
  transaction: SubmitDidTx;
}
