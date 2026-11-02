import { randomBytes } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import { p256 } from '@noble/curves/nist';
import { keccak_256 } from '@noble/hashes/sha3';
import { sha256 } from '@noble/hashes/sha256';
import {
  Interface,
  JsonRpcProvider,
  Wallet,
  getAddress,
  getBytes,
  hexlify,
  id,
  keccak256,
  toUtf8Bytes,
  zeroPadValue,
} from 'ethers';
import type { DIDDocument, VerificationMethodEntry } from '../common/verification-method';
import { bytesToHex, hexToBytes, normalizeHex } from '../common/crypto/hex';
import { decodeP256PublicMultibase, encodeP256PublicMultibase } from '../common/verification-method/multikey';
import type {
  CreateDID,
  CreateDidFromPublicKeyOptions,
  CreateDidFromPublicKeyWithTransactionOptions,
  CreateDidRegistrationPayloadOptions,
  CreatedDidFromPublicKey,
  CreatedDidRegistration,
  DIDGeneratorConfig,
  DIDType,
  GeneratedDID,
  DidRegistrationPayload,
  ParsedDidPublicKey,
  SubmitDidTx,
  SubmitDidRegistrationOptions,
  SubmitDidRegistrationResult,
} from './types';

const DEFAULT_DID_METHOD = 'did:nda:testnet';
const DEFAULT_DID_TYPE = 'people';
const CID_CONTEXT = 'https://www.w3.org/ns/cid/v1';
const SECP256K1_VM_TYPE = 'EcdsaSecp256k1VerificationKey2019';
const MULTIKEY_VM_TYPE = 'Multikey';
const DID_REGISTER_PATH = '/did/register';
const DEFAULT_RPC = 'https://rpc-testnet.pila.vn';
const DEFAULT_CHAIN_ID = 6789;
const DEFAULT_DID_ADDRESS = '0x0000000000000000000000000000000000018888';
const ATTRIBUTE_NAME = 'type';
const ATTRIBUTE_VALIDITY_SECONDS = 86400n;
const FALLBACK_GAS_LIMIT = 80_000n;
const DID_REGISTRY_ABI = [
  'function setAttribute(address identity, bytes32 name, bytes value, uint256 validity)',
];

export function parsePublicKeyToDid(
  publicKeyHex: string,
  didMethod = DEFAULT_DID_METHOD,
): ParsedDidPublicKey {
  const clean = normalizeHex(publicKeyHex).toLowerCase();
  const bytes = hexToBytes(clean);

  let curve: ParsedDidPublicKey['curve'];
  let address: string;

  switch (bytes.length) {
    case 32: {
      curve = 'hash';
      address = computeHashAddress(bytes);
      break;
    }
    case 33: {
      const secp = tryDecodeSecp256k1(bytes);
      if (secp !== null) {
        curve = 'secp256k1';
        address = computeEthereumAddress(secp);
        break;
      }

      const p256Point = tryDecodeP256(bytes);
      if (p256Point !== null) {
        curve = 'p256';
        address = computeSha256Address(p256Point.toRawBytes(false));
        break;
      }

      throw new Error('failed to decompress public key on secp256k1 or P-256');
    }
    case 64: {
      const secp = tryDecodeSecp256k1(new Uint8Array([0x04, ...bytes]));
      if (secp !== null) {
        curve = 'secp256k1';
        address = computeEthereumAddress(secp);
        break;
      }

      const p256Point = tryDecodeP256(new Uint8Array([0x04, ...bytes]));
      if (p256Point !== null) {
        curve = 'p256';
        address = computeSha256Address(p256Point.toRawBytes(false));
        break;
      }

      throw new Error('failed to parse 64-byte public key on secp256k1 or P-256');
    }
    case 65: {
      if (bytes[0] !== 0x04) {
        throw new Error('invalid uncompressed public key: must start with 0x04');
      }

      const secp = tryDecodeSecp256k1(bytes);
      if (secp !== null) {
        curve = 'secp256k1';
        address = computeEthereumAddress(secp);
        break;
      }

      const p256Point = tryDecodeP256(bytes);
      if (p256Point !== null) {
        curve = 'p256';
        address = computeSha256Address(bytes);
        break;
      }

      throw new Error('failed to unmarshal 65-byte public key on secp256k1 or P-256');
    }
    default:
      throw new Error(
        `invalid public key length: got ${bytes.length} bytes, expected 32, 33, 64, or 65`,
      );
  }

  return {
    curve,
    address,
    did: `${didMethod}:${address}`.toLowerCase(),
    publicKeyHex: `0x${clean}`,
  };
}

export function generateP256KeyPair(): { privateKeyHex: string; publicKeyHex: string } {
  const privateKey = p256.utils.randomPrivateKey();
  const publicKeyHex = bytesToHex(p256.getPublicKey(privateKey, false));
  return { privateKeyHex: `0x${bytesToHex(privateKey)}`, publicKeyHex: `0x${publicKeyHex}` };
}

export function generateDualCurveKeyPair(): {
  secp256k1: { privateKeyHex: string; publicKeyHex: string };
  p256: { privateKeyHex: string; publicKeyHex: string };
} {
  // Go GenerateDualCurveKeyPair: one P-256 scalar, reused on secp256k1 (n(P-256) < n(secp256k1)).
  const p256Pair = generateP256KeyPair();
  const scalar = hexToBytes(normalizeHex(p256Pair.privateKeyHex));
  const secpPub = hexlify(secp256k1.getPublicKey(scalar, false)).toLowerCase();
  const priv = p256Pair.privateKeyHex.toLowerCase();
  return {
    secp256k1: { privateKeyHex: priv, publicKeyHex: secpPub },
    p256: { privateKeyHex: priv, publicKeyHex: p256Pair.publicKeyHex.toLowerCase() },
  };
}

export function newP256MultikeyVM(
  didIdentifier: string,
  fragment: string,
  publicKeyHex: string,
): VerificationMethodEntry {
  const frag = fragment.startsWith('#') ? fragment : `#${fragment}`;
  return {
    id: `${didIdentifier}${frag}`,
    type: MULTIKEY_VM_TYPE,
    controller: didIdentifier,
    publicKeyMultibase: encodeP256PublicMultibase(hexToBytes(normalizeHex(publicKeyHex))),
  };
}

export function buildDidDocument(
  publicKeyHex: string,
  didIdentifier: string,
  didType = DEFAULT_DID_TYPE,
): DIDDocument {
  const clean = normalizeHex(publicKeyHex).toLowerCase();
  let curve: ParsedDidPublicKey['curve'] | null = null;
  try {
    curve = parsePublicKeyToDid(clean).curve;
  } catch {
    curve = null;
  }

  const vm: VerificationMethodEntry =
    curve === 'p256'
      ? newP256MultikeyVM(didIdentifier, '#key-1', clean)
      : {
          id: `${didIdentifier}#key-1`,
          type: SECP256K1_VM_TYPE,
          controller: didIdentifier,
          publicKeyHex: `0x${clean}`,
        };

  const contexts = ['https://w3id.org/security/v1', 'https://www.w3.org/ns/did/v1'];
  if (vm.type === MULTIKEY_VM_TYPE) contexts.push(CID_CONTEXT);

  return {
    '@context': contexts,
    id: didIdentifier,
    controller: didIdentifier,
    verificationMethod: [vm],
    authentication: [vm.id],
    assertionMethod: [vm.id],
    didDocumentMetadata: {
      type: didType,
      hash: '',
    },
  };
}

export function buildMixedCurveDidDocument(
  secp256k1PublicKeyHex: string,
  p256PublicKeyHex: string,
  didIdentifier: string,
  didType = DEFAULT_DID_TYPE,
): DIDDocument {
  const secp = normalizeHex(secp256k1PublicKeyHex).toLowerCase();
  const key1: VerificationMethodEntry = {
    id: `${didIdentifier}#key-1`,
    type: SECP256K1_VM_TYPE,
    controller: didIdentifier,
    publicKeyHex: `0x${secp}`,
  };
  const key2 = newP256MultikeyVM(didIdentifier, '#key-2', p256PublicKeyHex);
  return {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/v1',
      CID_CONTEXT,
    ],
    id: didIdentifier,
    controller: didIdentifier,
    verificationMethod: [key1, key2],
    authentication: [key1.id, key2.id],
    assertionMethod: [key1.id, key2.id],
    didDocumentMetadata: {
      type: didType,
      hash: '',
    },
  };
}

export function createDidFromPublicKey(
  publicKeyHex: string,
  options: CreateDidFromPublicKeyOptions = {},
): CreatedDidFromPublicKey {
  const parsed = parsePublicKeyToDid(
    publicKeyHex,
    options.didMethod ?? DEFAULT_DID_METHOD,
  );

  return {
    ...parsed,
    document: buildDidDocument(
      parsed.publicKeyHex,
      options.didIdentifier ?? parsed.did,
      options.didType ?? DEFAULT_DID_TYPE,
    ),
    did: (options.didIdentifier ?? parsed.did).toLowerCase(),
  };
}

export function createDidRegistrationPayload(
  publicKeyHex: string,
  options: CreateDidRegistrationPayloadOptions,
): CreatedDidRegistration {
  const created = createDidFromPublicKey(publicKeyHex, options);
  return {
    did: created.did,
    curve: created.curve,
    address: created.address,
    document: created.document,
    registration: {
      issuer_did: options.issuerDid,
      document: created.document,
      transaction: options.transaction,
    },
  };
}

export function createDidFromPublicKeyWithTransaction(
  publicKeyHex: string,
  options: CreateDidFromPublicKeyWithTransactionOptions,
): CreatedDidRegistration {
  return createDidRegistrationPayload(publicKeyHex, options);
}

export async function submitDidRegistration(
  options: SubmitDidRegistrationOptions,
): Promise<SubmitDidRegistrationResult> {
  const fetcher = options.fetcher ?? fetch;
  const base = options.apiURL.replace(/\/+$/, '');
  const path = (options.registerPath ?? DID_REGISTER_PATH).replace(/^\/+/, '');
  const url = `${base}/${path}`;
  const bodyPayload = {
    ...options.payload,
    transaction: {
      TxHex: options.payload.transaction.txHex,
      TxHash: options.payload.transaction.txHash,
    },
  };
  const response = await fetcher(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json',
      'x-api-key': options.apiKey,
    },
    body: JSON.stringify(bodyPayload),
    signal: options.signal,
  });

  const body = await response.text();
  if (response.status === 409) {
    throw new Error(`API conflict ${response.status}: ${body}`);
  }
  if (!response.ok) {
    throw new Error(`API error ${response.status}: ${body}`);
  }

  return { status: response.status, body };
}

export class DIDGenerator {
  private readonly config: Required<DIDGeneratorConfig>;
  private readonly contractInterface = new Interface(DID_REGISTRY_ABI);

  constructor(config: DIDGeneratorConfig = {}) {
    this.config = {
      rpc: config.rpc ?? DEFAULT_RPC,
      chainId: config.chainId ?? DEFAULT_CHAIN_ID,
      didAddress: config.didAddress ?? DEFAULT_DID_ADDRESS,
      method: config.method ?? DEFAULT_DID_METHOD,
    };
  }

  async generateDID(createDID: CreateDID): Promise<GeneratedDID> {
    const dual = createDID.withP256 ? generateDualCurveKeyPair() : null;
    const privateKey = dual ? dual.secp256k1.privateKeyHex : randomPrivateKeyHex();
    const wallet = new Wallet(privateKey);
    const address = wallet.address.toLowerCase();
    const publicKeyHex = dual
      ? dual.secp256k1.publicKeyHex
      : hexlify(secp256k1.getPublicKey(getBytes(privateKey), true)).toLowerCase();
    const did = `${this.config.method}:${address}`.toLowerCase();
    const document = dual
      ? buildMixedCurveDidDocument(
          publicKeyHex,
          dual.p256.publicKeyHex,
          did,
          createDID.type,
        )
      : buildDidDocument(publicKeyHex, did, createDID.type);

    if (createDID.metadata && Object.keys(createDID.metadata).length > 0) {
      document.didDocumentMetadata = {
        ...createDID.metadata,
        type: createDID.type,
        hash: createDID.hash ?? '',
      };
    }

    const transaction = await this.generateSetAttributeTx(
      privateKey,
      address,
      createDID.type,
    );

    const secret = {
      privateKeyHex: privateKey.toLowerCase(),
      ...(dual ? { p256PrivateKeyHex: dual.p256.privateKeyHex } : {}),
    };

    return {
      did,
      secret,
      document,
      transaction,
    };
  }

  async reGenerateDIDTX(
    privateKeyHex: string,
    didMetadata: Record<string, unknown>,
  ): Promise<SubmitDidTx> {
    const didType = didMetadata.type;
    if (typeof didType !== 'string' || didType.length === 0) {
      throw new Error('did type is required');
    }

    const wallet = new Wallet(withHexPrefix(privateKeyHex));
    return this.reGenerateSetAttributeTx(wallet.privateKey, didType as DIDType);
  }

  async generateSetAttributeTx(
    privateKeyHex: string,
    address: string,
    value: string,
  ): Promise<SubmitDidTx> {
    const wallet = new Wallet(withHexPrefix(privateKeyHex));
    const data = this.contractInterface.encodeFunctionData('setAttribute', [
      getAddress(address),
      this.prepareAttributeName(ATTRIBUTE_NAME),
      toUtf8Bytes(value),
      ATTRIBUTE_VALIDITY_SECONDS,
    ]);

    const signed = await wallet.signTransaction({
      type: 0,
      to: this.config.didAddress,
      chainId: this.config.chainId,
      nonce: 0,
      gasLimit: FALLBACK_GAS_LIMIT,
      gasPrice: 0n,
      value: 0,
      data,
    });

    return {
      txHex: stripHexPrefix(signed),
      txHash: keccak256(signed),
    };
  }

  async reGenerateSetAttributeTx(
    privateKeyHex: string,
    value: string,
  ): Promise<SubmitDidTx> {
    const wallet = new Wallet(withHexPrefix(privateKeyHex));
    const provider = new JsonRpcProvider(this.config.rpc, this.config.chainId);
    const nonce = await provider.getTransactionCount(wallet.address, 'pending');
    const feeData = await provider.getFeeData();
    const gasPrice = feeData.gasPrice ?? 0n;
    const data = this.contractInterface.encodeFunctionData('setAttribute', [
      getAddress(wallet.address),
      this.prepareAttributeName(ATTRIBUTE_NAME),
      toUtf8Bytes(value),
      ATTRIBUTE_VALIDITY_SECONDS,
    ]);

    let gasLimit = FALLBACK_GAS_LIMIT;
    try {
      gasLimit = await provider.estimateGas({
        from: wallet.address,
        to: this.config.didAddress,
        data,
        value: 0n,
      });
    } catch {
      gasLimit = FALLBACK_GAS_LIMIT;
    }

    const signed = await wallet.signTransaction({
      type: 0,
      to: this.config.didAddress,
      chainId: this.config.chainId,
      nonce,
      gasLimit,
      gasPrice,
      value: 0,
      data,
    });

    return {
      txHex: stripHexPrefix(signed),
      txHash: keccak256(signed),
    };
  }

  private prepareAttributeName(name: string) {
    if (name.length === 0) {
      throw new Error('name is empty');
    }
    if (name.length > 32) {
      throw new Error('name exceeds 32 bytes');
    }
    return zeroPadValue(hexlify(toUtf8Bytes(name)), 32);
  }
}

function tryDecodeSecp256k1(bytes: Uint8Array) {
  try {
    return secp256k1.ProjectivePoint.fromHex(bytes);
  } catch {
    return null;
  }
}

function tryDecodeP256(bytes: Uint8Array) {
  try {
    return p256.ProjectivePoint.fromHex(bytes);
  } catch {
    return null;
  }
}

function computeEthereumAddress(point: { toRawBytes: (isCompressed?: boolean) => Uint8Array }) {
  const uncompressed = point.toRawBytes(false);
  const hash = keccak_256(uncompressed.subarray(1));
  return `0x${bytesToHex(hash.subarray(12))}`.toLowerCase();
}

function computeSha256Address(bytes: Uint8Array) {
  const hash = sha256(bytes);
  return `0x${bytesToHex(hash.subarray(12))}`.toLowerCase();
}

function computeHashAddress(bytes: Uint8Array) {
  const hash = keccak_256(bytes);
  return `0x${bytesToHex(hash.subarray(12))}`.toLowerCase();
}

function randomPrivateKeyHex() {
  return withHexPrefix(bytesToHex(randomBytes(32)));
}

function withHexPrefix(value: string) {
  return value.startsWith('0x') ? value : `0x${value}`;
}

function canonicalVmId(did: string, idOrFragment: string): string {
  return idOrFragment.startsWith('#') ? `${did}${idOrFragment}` : idOrFragment;
}

function vmTypeFor(vm: VerificationMethodEntry): string {
  if (vm.publicKeyJwk) {
    throw new Error(
      'publicKeyJwk is not supported: publish secp256k1 as publicKeyHex or P-256 as publicKeyMultibase',
    );
  }
  const hasHex = Boolean(vm.publicKeyHex);
  const hasMultibase = Boolean(vm.publicKeyMultibase);
  if (hasHex && hasMultibase) {
    throw new Error('verification method must have publicKeyHex or publicKeyMultibase, not both');
  }
  if (hasHex) return SECP256K1_VM_TYPE;
  if (hasMultibase) return MULTIKEY_VM_TYPE;
  throw new Error('verification method must have either publicKeyHex or publicKeyMultibase');
}

/** Rejects empty/duplicate VM ids, type/material mismatch, and dangling purpose refs. */
export function validateDidDocument(doc: DIDDocument | null | undefined): void {
  if (!doc) throw new Error('DID document is nil');
  const seen = new Set<string>();
  doc.verificationMethod.forEach((vm, i) => {
    if (!vm.id) throw new Error(`verificationMethod[${i}]: id is empty`);
    if (seen.has(vm.id)) {
      throw new Error(`verificationMethod: duplicate id ${vm.id}`);
    }
    seen.add(vm.id);
    const expected = vmTypeFor(vm);
    if (vm.type !== expected) {
      throw new Error(
        `verificationMethod[${i}] (${vm.id}): type ${JSON.stringify(vm.type)} does not match its key material: expected ${expected}`,
      );
    }
    if (vm.publicKeyHex) {
      const bytes = hexToBytes(normalizeHex(vm.publicKeyHex));
      if (![33, 64, 65].includes(bytes.length)) {
        throw new Error(`verificationMethod[${i}] (${vm.id}): invalid publicKeyHex length ${bytes.length}`);
      }
    }
    if (vm.publicKeyMultibase) {
      try {
        decodeP256PublicMultibase(vm.publicKeyMultibase);
      } catch (err) {
        throw new Error(
          `verificationMethod[${i}] (${vm.id}): invalid publicKeyMultibase: ${(err as Error).message}`,
        );
      }
    }
    if (vm.controller && doc.id && vm.controller !== doc.id) {
      throw new Error(`verificationMethod[${i}] (${vm.id}): controller ${vm.controller} does not match document id`);
    }
  });
  for (const [name, refs] of [
    ['authentication', doc.authentication ?? []],
    ['assertionMethod', doc.assertionMethod ?? []],
  ] as const) {
    for (const ref of refs) {
      if (!seen.has(canonicalVmId(doc.id, ref))) {
        throw new Error(`${name} references unknown verification method ${JSON.stringify(ref)}`);
      }
    }
  }
}

function stripHexPrefix(value: string) {
  return value.startsWith('0x') ? value.slice(2) : value;
}
