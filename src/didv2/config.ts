import type { DIDConfig, DIDOption, VerificationMethodSpec } from './types';
import type { SignerProvider } from './signer';

export const DefaultRPC = 'https://rpc-new.pila.vn';
export const DefaultChainID = 704n;
export const DefaultDIDSMCAddress = '0x75e7b09a24bce5a921babe27b62ec7bfe2230d6a';
export const DefaultMethod = 'did:nda';

export function defaultDIDConfig(): DIDConfig {
  return {
    rpc: DefaultRPC,
    chainId: DefaultChainID,
    didSmcAddr: DefaultDIDSMCAddress,
    method: DefaultMethod,
    nonce: 0n,
    epoch: 0n,
    capId: '',
    syncEpoch: false,
    syncNonce: false,
    extraVMs: [],
    enableP256VM: false,
  };
}

export function WithRPC(rpc: string): DIDOption {
  return (c) => {
    c.rpc = rpc;
  };
}

export function WithDIDChainID(chainId: bigint | number): DIDOption {
  return (c) => {
    c.chainId = BigInt(chainId);
  };
}

export function WithDIDAddressSMC(addr: string): DIDOption {
  return (c) => {
    c.didSmcAddr = addr;
  };
}

export function WithMethod(method: string): DIDOption {
  return (c) => {
    c.method = method;
  };
}

export function WithEpoch(epoch: bigint | number): DIDOption {
  return (c) => {
    c.epoch = BigInt(epoch);
  };
}

export function WithIssuerSignerProvider(p: SignerProvider): DIDOption {
  return (c) => {
    c.issuerSigner = p;
  };
}

export function WithDIDSignerProvider(p: SignerProvider): DIDOption {
  return (c) => {
    c.didSigner = p;
  };
}

export function WithSyncEpoch(sync: boolean): DIDOption {
  return (c) => {
    c.syncEpoch = sync;
  };
}

export function WithSyncNonce(sync: boolean): DIDOption {
  return (c) => {
    c.syncNonce = sync;
  };
}

export function WithNonce(nonce: bigint | number): DIDOption {
  return (c) => {
    c.nonce = BigInt(nonce);
  };
}

export function WithCapID(capId: string): DIDOption {
  return (c) => {
    c.capId = capId;
  };
}

export function WithVerificationMethods(...specs: VerificationMethodSpec[]): DIDOption {
  return (c) => {
    c.extraVMs = c.extraVMs.concat(specs);
  };
}

export function WithP256VerificationMethod(): DIDOption {
  return (c) => {
    c.enableP256VM = true;
  };
}

export function WithDIDConfig(config: DIDConfig): DIDOption {
  return (c) => {
    c.rpc = config.rpc;
    c.chainId = config.chainId;
    c.didSmcAddr = config.didSmcAddr.toLowerCase();
    c.method = config.method;
    c.issuerSigner = config.issuerSigner;
    c.didSigner = config.didSigner;
    c.capId = config.capId;
    c.epoch = config.epoch;
    c.nonce = config.nonce;
    c.syncEpoch = config.syncEpoch;
    c.syncNonce = config.syncNonce;
    c.extraVMs = config.extraVMs.slice();
    c.enableP256VM = config.enableP256VM;
  };
}
