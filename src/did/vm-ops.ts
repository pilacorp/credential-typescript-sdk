/**
 * DIDv2 verification-method mutation — Node port of
 * didv2/did/verification_method_ops.go
 */
import { secp256k1 } from '@noble/curves/secp256k1';
import type { DIDDocument, VerificationMethodEntry } from '../common/verification-method';
import { bytesToHex, hexToBytes, normalizeHex } from '../common/crypto/hex';

export type VerificationPurpose = 'authentication' | 'assertionMethod';

const CID_CONTEXT = 'https://www.w3.org/ns/cid/v1';
const SECP256K1_VM_TYPE = 'EcdsaSecp256k1VerificationKey2019';
const MULTIKEY_VM_TYPE = 'Multikey';
const SUPPORTED: VerificationPurpose[] = ['authentication', 'assertionMethod'];

export function findVerificationMethod(
  doc: DIDDocument | null | undefined,
  idOrFragment: string,
): VerificationMethodEntry | undefined {
  if (!doc) return undefined;
  const target = canonicalVmId(doc.id, idOrFragment);
  return doc.verificationMethod.find((vm) => canonicalVmId(doc.id, vm.id) === target);
}

export function addVerificationMethod(
  doc: DIDDocument,
  vm: Partial<VerificationMethodEntry>,
  purposes: VerificationPurpose[] = [],
): string {
  if (!doc) throw new Error('document is nil');
  if (!doc.id) throw new Error('document.id is required');
  const expectedType = vmTypeFor(vm);
  validatePurposes(purposes);

  const next: VerificationMethodEntry = {
    id: vm.id ? canonicalVmId(doc.id, vm.id) : nextSequentialKid(doc),
    type: vm.type || expectedType,
    controller: vm.controller || doc.id,
    publicKeyHex: vm.publicKeyHex,
    publicKeyMultibase: vm.publicKeyMultibase,
    publicKeyJwk: vm.publicKeyJwk,
    revoked: vm.revoked,
    revocationReason: vm.revocationReason,
  };
  if (next.type !== expectedType) {
    throw new Error(
      `verification method type ${JSON.stringify(next.type)} does not match its key material: expected ${expectedType}`,
    );
  }
  if (findVerificationMethod(doc, next.id)) {
    throw new Error(`verification method already exists: ${next.id}`);
  }
  const existing = findByKeyFingerprint(doc, keyFingerprint(next));
  if (existing) {
    throw new Error(`verification method with the same public key already exists: ${existing}`);
  }
  doc.verificationMethod.push(next);
  if (next.type === MULTIKEY_VM_TYPE) ensureContext(doc, CID_CONTEXT);
  for (const p of purposes) addPurpose(doc, p, next.id);
  return next.id;
}

export function rotateVerificationMethod(
  doc: DIDDocument,
  oldKid: string,
  newVM: Partial<VerificationMethodEntry>,
  reason = 'superseded',
  revokedAt: Date = new Date(),
): string {
  if (!doc) throw new Error('document is nil');
  if (!oldKid) throw new Error('old_kid is required');
  const old = findVerificationMethod(doc, oldKid);
  if (!old) throw new Error(`verification method not found: ${oldKid}`);
  if (old.revoked) throw new Error(`verification method ${JSON.stringify(old.id)} is already revoked`);
  const purposes = purposesOfKid(doc, old.id);
  const newID = addVerificationMethod(doc, newVM, purposes);
  const after = findVerificationMethod(doc, oldKid);
  if (!after) throw new Error(`verification method index mismatch after append: ${oldKid}`);
  after.revoked = revokedAt;
  after.revocationReason = reason || 'superseded';
  ensureContext(doc, CID_CONTEXT);
  return newID;
}

export function revokeVerificationMethod(
  doc: DIDDocument,
  kid: string,
  reason: string,
  revokedAt: Date = new Date(),
): void {
  if (!doc) throw new Error('document is nil');
  if (!kid) throw new Error('kid is required');
  if (!reason) throw new Error('reason is required');
  const vm = findVerificationMethod(doc, kid);
  if (!vm) throw new Error(`verification method not found: ${kid}`);
  if (vm.revoked) {
    throw new Error(
      `verification method ${JSON.stringify(vm.id)} is already revoked at ${vm.revoked.toISOString()} (reason: ${vm.revocationReason})`,
    );
  }
  vm.revoked = revokedAt;
  vm.revocationReason = reason;
  ensureContext(doc, CID_CONTEXT);
}

export function addVerificationMethodPurposes(
  doc: DIDDocument,
  kid: string,
  purposes: VerificationPurpose[],
): void {
  if (!doc) throw new Error('document is nil');
  if (!kid) throw new Error('kid is required');
  if (!purposes.length) throw new Error('purposes is required');
  const vm = findVerificationMethod(doc, kid);
  if (!vm) throw new Error(`verification method not found: ${kid}`);
  if (vm.revoked) throw new Error(`verification method ${JSON.stringify(vm.id)} is revoked`);
  validatePurposes(purposes);
  for (const p of purposes) addPurpose(doc, p, kid);
}

export function removeVerificationMethodPurposes(
  doc: DIDDocument,
  kid: string,
  purposes: VerificationPurpose[],
): void {
  if (!doc) throw new Error('document is nil');
  if (!kid) throw new Error('kid is required');
  if (!purposes.length) throw new Error('purposes is required');
  if (!findVerificationMethod(doc, kid)) throw new Error(`verification method not found: ${kid}`);
  validatePurposes(purposes);
  for (const p of purposes) removePurpose(doc, p, kid);
}

function vmTypeFor(vm: Partial<VerificationMethodEntry>): string {
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

function ensureContext(doc: DIDDocument, ctx: string): void {
  if (!doc['@context'].includes(ctx)) doc['@context'] = [...doc['@context'], ctx];
}

function findByKeyFingerprint(doc: DIDDocument, fp: string): string {
  if (!fp) return '';
  const hit = doc.verificationMethod.find((vm) => keyFingerprint(vm) === fp);
  return hit?.id ?? '';
}

function keyFingerprint(vm: Partial<VerificationMethodEntry>): string {
  if (vm.publicKeyHex) return `publicKeyHex:${normalizeSecp256k1Hex(vm.publicKeyHex)}`;
  if (vm.publicKeyMultibase) return `publicKeyMultibase:${vm.publicKeyMultibase}`;
  return '';
}

function normalizeSecp256k1Hex(h: string): string {
  const trimmed = normalizeHex(h).toLowerCase();
  try {
    const raw = hexToBytes(trimmed);
    return bytesToHex(secp256k1.ProjectivePoint.fromHex(raw).toRawBytes(true));
  } catch {
    return trimmed;
  }
}

function validatePurposes(purposes: VerificationPurpose[]): void {
  for (const p of purposes) {
    if (!SUPPORTED.includes(p)) throw new Error(`unsupported purpose: ${p}`);
  }
}

function addPurpose(doc: DIDDocument, p: VerificationPurpose, kid: string): void {
  if (p === 'authentication') doc.authentication = addRefNormalized(doc.authentication, kid, doc.id);
  else doc.assertionMethod = addRefNormalized(doc.assertionMethod, kid, doc.id);
}

function removePurpose(doc: DIDDocument, p: VerificationPurpose, kid: string): void {
  if (p === 'authentication') doc.authentication = removeRefNormalized(doc.authentication, kid, doc.id);
  else doc.assertionMethod = removeRefNormalized(doc.assertionMethod, kid, doc.id);
}

function addRefNormalized(arr: string[], kid: string, did: string): string[] {
  const target = canonicalVmId(did, kid);
  const seen = new Set<string>();
  const out: string[] = [];
  for (const x of arr ?? []) {
    const c = canonicalVmId(did, x);
    if (seen.has(c)) continue;
    seen.add(c);
    out.push(c);
  }
  if (!seen.has(target)) out.push(target);
  return out;
}

function removeRefNormalized(arr: string[], kid: string, did: string): string[] {
  const target = canonicalVmId(did, kid);
  const seen = new Set<string>();
  const out: string[] = [];
  for (const x of arr ?? []) {
    const c = canonicalVmId(did, x);
    if (c === target || seen.has(c)) continue;
    seen.add(c);
    out.push(c);
  }
  return out;
}

function purposesOfKid(doc: DIDDocument, kid: string): VerificationPurpose[] {
  const out: VerificationPurpose[] = [];
  if (containsKidRef(doc.authentication, kid, doc.id)) out.push('authentication');
  if (containsKidRef(doc.assertionMethod, kid, doc.id)) out.push('assertionMethod');
  return out;
}

function containsKidRef(arr: string[], kid: string, did: string): boolean {
  const target = canonicalVmId(did, kid);
  return (arr ?? []).some((x) => canonicalVmId(did, x) === target);
}

function nextSequentialKid(doc: DIDDocument): string {
  let maxN = 0;
  for (const vm of doc.verificationMethod) {
    const frag = vm.id.startsWith(doc.id) ? vm.id.slice(doc.id.length) : vm.id;
    if (!frag.startsWith('#key-')) continue;
    const n = Number.parseInt(frag.slice('#key-'.length), 10);
    if (!Number.isNaN(n) && n > maxN) maxN = n;
  }
  return `${doc.id}#key-${maxN + 1}`;
}

export function canonicalVmId(did: string, idOrFragment: string): string {
  if (idOrFragment.startsWith('#')) return did + idOrFragment;
  return idOrFragment;
}
