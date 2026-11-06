import { keccak256 } from 'ethers';
import { secp256k1 } from '@noble/curves/secp256k1';
import { p256 } from '@noble/curves/nist';
import { keccak_256 } from '@noble/hashes/sha3';
import type { DIDDocument, VerificationMethodEntry } from '../common/verification-method';
import { transform } from '../common/jsoncanonicalizer/jsoncanonicalizer';
import { formatRFC3339Nano } from '../common/util/time';
import { parseRFC3339Strict } from '../common/verification-method/verification-method';
import { bytesToHex, hexToBytes, normalizeHex } from '../common/crypto/hex';
import { encodeP256PublicMultibase } from '../common/verification-method/multikey';
import { generateDualCurveKeyPair as generateLegacyDualCurveKeyPair } from '../did/did';
import {
  DIDTypePeople,
  PurposeAssertionMethod,
  PurposeAuthentication,
  didTypeString,
  type DIDType,
  type KeyPair,
  type VerificationMethodSpec,
  type VerificationPurpose,
} from './types';

const SECP256K1_VM_TYPE = 'EcdsaSecp256k1VerificationKey2019';
const MULTIKEY_VM_TYPE = 'Multikey';
const CID_CONTEXT = 'https://www.w3.org/ns/cid/v1';

export function generateECDSAKeyPair(): KeyPair {
  const priv = secp256k1.utils.randomPrivateKey();
  const pub = secp256k1.getPublicKey(priv, true);
  return {
    privateKeyHex: `0x${bytesToHex(priv)}`,
    publicKeyHex: `0x${bytesToHex(pub)}`,
    address: addressFromPublicKeyHex(`0x${bytesToHex(pub)}`),
  };
}

/**
 * One scalar published as both a secp256k1 key pair and a P-256 public key
 * (Go's GenerateDualCurveKeyPair).
 */
export function generateDualCurveKeyPair(): KeyPair {
  const pair = generateLegacyDualCurveKeyPair();
  const scalar = hexToBytes(normalizeHex(pair.secp256k1.privateKeyHex));
  const compressed = secp256k1.getPublicKey(scalar, true);
  const p256Pub = p256.getPublicKey(scalar, false);
  return {
    privateKeyHex: `0x${bytesToHex(scalar)}`,
    publicKeyHex: `0x${bytesToHex(compressed)}`,
    address: addressFromPublicKeyHex(`0x${bytesToHex(compressed)}`),
    p256PublicKeyXY: {
      x: bytesToHex(p256Pub.slice(1, 33)),
      y: bytesToHex(p256Pub.slice(33, 65)),
    },
  };
}

/** @deprecated Use generateDualCurveKeyPair. */
export const generateDualCurveDIDKeyPair = generateDualCurveKeyPair;

export function canonicalVMID(did: string, idOrFragment: string): string {
  return idOrFragment.startsWith('#') ? `${did}${idOrFragment}` : idOrFragment;
}

export function newSecp256k1VM(did: string, fragment: string, publicKeyHex: string): VerificationMethodEntry {
  return {
    id: canonicalVMID(did, fragment),
    type: SECP256K1_VM_TYPE,
    controller: did,
    publicKeyHex,
  };
}

export function newP256MultikeyVM(
  did: string,
  fragment: string,
  p256UncompressedOrXY: Uint8Array | { x: string; y: string },
): VerificationMethodEntry {
  let point: Uint8Array;
  if (p256UncompressedOrXY instanceof Uint8Array) {
    point = p256UncompressedOrXY;
  } else {
    point = hexToBytes(`04${p256UncompressedOrXY.x}${p256UncompressedOrXY.y}`);
  }
  // 64 bytes is the raw X||Y form; SEC1 (33 compressed / 65 uncompressed) passes through.
  if (point.length === 64) point = new Uint8Array([0x04, ...point]);
  let uncompressed: Uint8Array;
  try {
    uncompressed = p256.ProjectivePoint.fromHex(point).toRawBytes(false);
  } catch {
    throw new Error('NewP256MultikeyVM requires a P-256 public key');
  }
  return {
    id: canonicalVMID(did, fragment),
    type: MULTIKEY_VM_TYPE,
    controller: did,
    publicKeyMultibase: encodeP256PublicMultibase(uncompressed),
  };
}

export function newSpec(vm: VerificationMethodEntry, ...purposes: VerificationPurpose[]): VerificationMethodSpec {
  return { vm, purposes: purposes.length ? purposes : undefined };
}

export function generateDIDDocument(
  didPublicKey: string,
  did: string,
  hash: string,
  issuerDID: string,
  didType: DIDType = DIDTypePeople,
  metadata: Record<string, unknown> | null = null,
  extraVMs: VerificationMethodSpec[] = [],
): DIDDocument | null {
  const docMetadata: Record<string, unknown> = { ...(metadata ?? {}) };
  const typeName = didTypeString(didType);
  if (typeName) docMetadata.type = typeName;
  if (hash) docMetadata.hash = hash;

  const specs: VerificationMethodSpec[] = [
    newSpec(newSecp256k1VM(did, '#key-1', didPublicKey)),
    ...extraVMs,
  ];
  const built = newVerificationMethods(...specs);
  if (!built) return null;

  return {
    '@context': documentContext(built.vms),
    id: did,
    controller: issuerDID,
    verificationMethod: built.vms,
    authentication: built.authentication,
    assertionMethod: built.assertionMethod,
    didDocumentMetadata: sortObject(docMetadata),
  };
}

export function newVerificationMethods(...specs: VerificationMethodSpec[]): {
  vms: VerificationMethodEntry[];
  authentication: string[];
  assertionMethod: string[];
} | null {
  const vms: VerificationMethodEntry[] = [];
  const authentication: string[] = [];
  const assertionMethod: string[] = [];
  for (const s of specs) {
    vms.push(s.vm);
    const purposes = s.purposes?.length
      ? s.purposes
      : [PurposeAuthentication, PurposeAssertionMethod];
    for (const p of purposes) {
      if (p === PurposeAuthentication) authentication.push(s.vm.id);
      else if (p === PurposeAssertionMethod) assertionMethod.push(s.vm.id);
      else return null;
    }
  }
  return { vms, authentication, assertionMethod };
}

function documentContext(vms: VerificationMethodEntry[]): string[] {
  const ctx = ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/v1'];
  if (vms.some((vm) => vm.type === MULTIKEY_VM_TYPE)) ctx.push(CID_CONTEXT);
  return ctx;
}

export function findVerificationMethod(
  doc: DIDDocument | null | undefined,
  idOrFragment: string,
): VerificationMethodEntry | undefined {
  if (!doc) return undefined;
  const target = canonicalVMID(doc.id, idOrFragment);
  return doc.verificationMethod.find((vm) => canonicalVMID(doc.id, vm.id) === target);
}

export function validateDIDDocument(doc: DIDDocument | null | undefined): void {
  if (!doc) throw new Error('DID document is nil');
  const seen = new Set<string>();
  doc.verificationMethod.forEach((vm, i) => {
    if (!vm.id) throw new Error(`verificationMethod[${i}]: id is empty`);
    if (seen.has(vm.id)) {
      throw new Error(`verificationMethod: duplicate id ${vm.id} (#key-1 and #key-2 are reserved by GenerateDID)`);
    }
    seen.add(vm.id);
    const expected = vmTypeFor(vm);
    if (vm.type !== expected) {
      throw new Error(
        `verificationMethod[${i}] (${vm.id}): type ${JSON.stringify(vm.type)} does not match its key material: expected ${expected}`,
      );
    }
  });
  for (const [name, refs] of [
    ['authentication', doc.authentication],
    ['assertionMethod', doc.assertionMethod],
  ] as const) {
    for (const ref of refs) {
      if (!seen.has(canonicalVMID(doc.id, ref))) {
        throw new Error(`${name} references unknown verification method ${JSON.stringify(ref)}`);
      }
    }
  }
}

function vmTypeFor(vm: VerificationMethodEntry): string {
  if (vm.publicKeyJwk && Object.keys(vm.publicKeyJwk).length > 0) {
    throw new Error('publicKeyJwk is not supported: publish secp256k1 as publicKeyHex or P-256 as publicKeyMultibase');
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

export function hashDIDDocument(doc: DIDDocument): string {
  const marshaled = JSON.stringify(didDocumentJSON(doc));
  const canonical = transform(marshaled);
  return keccak256(canonical).toLowerCase();
}

export function didDocumentJSON(doc: DIDDocument): Record<string, unknown> {
  // Go's DIDDocument marshals none of these fields with omitempty, and a nil
  // Go slice/map marshals as `null` (not `[]`/`{}`), so the hashed bytes carry
  // `null` for an absent field. Mirror that exactly for a byte-identical DocHash.
  return {
    '@context': doc['@context'] ?? null,
    id: doc.id ?? '',
    controller: doc.controller ?? '',
    verificationMethod: doc.verificationMethod ? doc.verificationMethod.map(vmJSON) : null,
    authentication: doc.authentication ?? null,
    assertionMethod: doc.assertionMethod ?? null,
    didDocumentMetadata: doc.didDocumentMetadata == null ? null : sortObject(doc.didDocumentMetadata),
  };
}

function vmJSON(vm: VerificationMethodEntry): Record<string, unknown> {
  // Go writes id/type/controller without omitempty (a missing one is ""), and
  // omits an empty publicKeyJwk map.
  const out: Record<string, unknown> = {
    id: vm.id ?? '',
    type: vm.type ?? '',
    controller: vm.controller ?? '',
  };
  if (vm.publicKeyHex) out.publicKeyHex = vm.publicKeyHex;
  if (vm.publicKeyJwk && Object.keys(vm.publicKeyJwk).length > 0) out.publicKeyJwk = vm.publicKeyJwk;
  if (vm.publicKeyMultibase) out.publicKeyMultibase = vm.publicKeyMultibase;
  // Go marshals *time.Time as RFC3339Nano with the original offset and
  // nanoseconds; keep the parsed text while it still denotes the same instant.
  if (vm.revoked) out.revoked = revokedText(vm);
  if (vm.revocationReason) out.revocationReason = vm.revocationReason;
  return out;
}

function revokedText(vm: VerificationMethodEntry): string {
  const kept = vm.revokedText;
  if (kept) {
    try {
      if (parseRFC3339Strict(kept).date.getTime() === vm.revoked!.getTime()) return kept;
    } catch {
      /* fall through to the Date value */
    }
  }
  return formatRFC3339Nano(vm.revoked!);
}

function sortObject(input: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(input).sort()) {
    out[key] = sortValue(input[key]);
  }
  return out;
}

function sortValue(v: unknown): unknown {
  // A Date serializes as Go marshals time.Time (RFC3339Nano), not as {}.
  if (v instanceof Date) return formatRFC3339Nano(v);
  // Go: []byte marshals as base64; NaN/Inf make json.Marshal fail.
  if (v instanceof Uint8Array) return Buffer.from(v).toString('base64');
  if (typeof v === 'number' && !Number.isFinite(v)) {
    throw new Error(`json: unsupported value: ${v}`);
  }
  if (Array.isArray(v)) return v.map(sortValue);
  // A Map with string keys is Go's map[string]any; a Set has no Go counterpart.
  if (v instanceof Map) {
    const o: Record<string, unknown> = {};
    for (const [k, val] of v) {
      if (typeof k !== 'string') throw new Error('json: unsupported map key type');
      o[k] = val;
    }
    return sortObject(o);
  }
  if (v instanceof Set) throw new Error('json: unsupported type: Set');
  if (v && typeof v === 'object') return sortObject(v as Record<string, unknown>);
  return v;
}

export function addressFromPublicKeyHex(publicKeyHex: string): string {
  const bytes = hexToBytes(normalizeHex(publicKeyHex));
  let uncompressed: Uint8Array;
  if (bytes.length === 33 && (bytes[0] === 0x02 || bytes[0] === 0x03)) {
    uncompressed = secp256k1.ProjectivePoint.fromHex(bytes).toRawBytes(false);
  } else if (bytes.length === 65 && bytes[0] === 0x04) {
    // Reject a point that is not on the curve, like Go's crypto.UnmarshalPubkey.
    uncompressed = secp256k1.ProjectivePoint.fromHex(bytes).toRawBytes(false);
  } else {
    throw new Error(
      `unsupported public key format: expected 33 bytes (compressed) or 65 bytes (uncompressed), got ${bytes.length} bytes`,
    );
  }
  const hash = keccak_256(uncompressed.slice(1));
  return `0x${bytesToHex(hash.slice(12))}`.toLowerCase();
}
