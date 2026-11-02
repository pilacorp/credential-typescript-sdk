import {
  addressFromPublicKeyHex,
  generateDIDDocument,
  generateDualCurveDIDKeyPair,
  hashDIDDocument,
  newP256MultikeyVM,
  newSpec,
  validateDIDDocument,
} from './document';
import { Contract } from './didcontract';
import { generateCapID, generateIssueDIDSignature, type IssuerSignature } from './issuer';
import { DefaultProvider } from './signer';
import type { DIDConfig, DIDOption, DIDTxResult, DIDType } from './types';
import { toDID } from './types';
import { DefaultDIDSMCAddress, DefaultMethod, defaultDIDConfig } from './config';

export class DIDGenerator {
  private readonly baseConfig: DIDConfig;
  private readonly didContract: Contract;

  constructor(options: DIDOption[] = []) {
    const cfg = defaultDIDConfig();
    for (const opt of options) opt(cfg);
    this.baseConfig = cfg;
    this.didContract = new Contract({
      rpcUrl: cfg.rpc,
      contractAddress: cfg.didSmcAddr || DefaultDIDSMCAddress,
      chainId: cfg.chainId,
    });
  }

  async generateDID(
    didType: DIDType,
    hash: string,
    metadata: Record<string, unknown> | null,
    ...options: DIDOption[]
  ): Promise<DIDTxResult> {
    const cfg = this.resolveConfig(...options);
    const keyPair = generateDualCurveDIDKeyPair();
    const didSigner = new DefaultProvider(keyPair.privateKeyHex);
    options = options.concat([(c) => {
      c.didSigner = didSigner;
    }]);
    if (cfg.enableP256VM && keyPair.p256PublicKeyXY) {
      const didAddr = addressFromPublicKeyHex(keyPair.publicKeyHex);
      const p256VM = newP256MultikeyVM(toDID(cfg.method || DefaultMethod, didAddr), '#key-2', keyPair.p256PublicKeyXY);
      options = options.concat([(c) => {
        c.extraVMs = c.extraVMs.concat(newSpec(p256VM));
      }]);
    }
    const didTx = await this.generateDIDTX(didType, keyPair.publicKeyHex, hash, metadata, ...options);
    didTx.secret = { privateKeyHex: keyPair.privateKeyHex };
    return didTx;
  }

  async generateDIDTX(
    didType: DIDType,
    didPublicKeyHex: string,
    hash: string,
    metadata: Record<string, unknown> | null,
    ...options: DIDOption[]
  ): Promise<DIDTxResult> {
    const cfg = this.resolveConfig(...options);
    if (!cfg.issuerSigner) throw new Error('issuer signer is required');
    const issuerAddr = cfg.issuerSigner.getAddress();
    const didAddr = addressFromPublicKeyHex(didPublicKeyHex);
    const issuerSig = await this.generateIssuerSignature(didType, didAddr, issuerAddr, (c) => Object.assign(c, cfg));
    const issuerDID = toDID(cfg.method, issuerAddr);
    const didIdentifier = toDID(cfg.method, didAddr);
    const didDoc = generateDIDDocument(didPublicKeyHex, didIdentifier, hash, issuerDID, didType, metadata, cfg.extraVMs);
    if (!didDoc) throw new Error('invalid DID document: build failed');
    validateDIDDocument(didDoc);
    const docHash = hashDIDDocument(didDoc);
    const txResult = await this.generateDIDCreateTransaction(
      didType,
      docHash,
      didAddr,
      issuerAddr,
      issuerSig,
      (c) => Object.assign(c, cfg),
    );
    return { did: didIdentifier, document: didDoc, transaction: txResult };
  }

  async generateIssuerSignature(
    didType: DIDType,
    didAddr: string,
    issuerAddr: string,
    ...options: DIDOption[]
  ): Promise<IssuerSignature> {
    const cfg = this.resolveConfig(...options);
    if (cfg.syncEpoch) cfg.epoch = await this.didContract.getCapabilityEpoch(issuerAddr);
    if (!cfg.issuerSigner) throw new Error('issuer signer is required');
    return generateIssueDIDSignature(
      {
        contractAddress: this.baseConfig.didSmcAddr,
        issuerAddress: issuerAddr,
        didAddress: didAddr,
        didType,
        epoch: cfg.epoch,
        capId: cfg.capId,
      },
      cfg.issuerSigner,
    );
  }

  async generateDIDCreateTransaction(
    didType: DIDType,
    docHash: string,
    didAddr: string,
    issuerAddr: string,
    issuerSig: IssuerSignature,
    ...options: DIDOption[]
  ) {
    const cfg = this.resolveConfig(...options);
    if (cfg.syncNonce) cfg.nonce = await this.didContract.getNonce(didAddr);
    if (!cfg.didSigner) throw new Error('did signer is required');
    return this.didContract.createDIDTx(
      {
        issuerAddress: issuerAddr,
        issuerSig,
        docHash,
        didType,
        capId: cfg.capId,
        nonce: cfg.nonce,
      },
      cfg.didSigner,
    );
  }

  async generateSetDocumentHashTransaction(
    docHash: string,
    didAddr: string,
    issuerSig: IssuerSignature,
    ...options: DIDOption[]
  ) {
    const cfg = this.resolveConfig(...options);
    if (!cfg.didSigner) throw new Error('did signer is required');
    if (!issuerSig) throw new Error('issuer signature is required');
    if (cfg.syncNonce) cfg.nonce = await this.didContract.getNonce(didAddr);
    return this.didContract.setDocumentHashTx(
      {
        didAddress: didAddr,
        docHash,
        capId: cfg.capId,
        issuerSig,
        nonce: cfg.nonce,
      },
      cfg.didSigner,
    );
  }

  async generateSetDocumentHashByIssuerTransaction(docHash: string, didAddr: string, ...options: DIDOption[]) {
    const cfg = this.resolveConfig(...options);
    if (!cfg.issuerSigner) throw new Error('issuer signer is required');
    if (cfg.syncNonce) cfg.nonce = await this.didContract.getNonce(cfg.issuerSigner.getAddress());
    return this.didContract.setDocumentHashByIssuerTx(
      { didAddress: didAddr, docHash, nonce: cfg.nonce },
      cfg.issuerSigner,
    );
  }

  private resolveConfig(...options: DIDOption[]): DIDConfig {
    const cfg: DIDConfig = {
      ...this.baseConfig,
      extraVMs: this.baseConfig.extraVMs.slice(),
    };
    for (const opt of options) opt(cfg);
    if (!cfg.capId) cfg.capId = generateCapID();
    return cfg;
  }
}

export function newDIDGenerator(...options: DIDOption[]): DIDGenerator {
  return new DIDGenerator(options);
}
