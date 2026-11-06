/**
 * Verification method selection — Node port of
 * credential/common/verification-method/selector.go
 *
 * SelectLatestActiveVMForPurpose: picks the VM that has the highest
 * `#key-N` index among unrevoked entries granted the requested purpose.
 *
 * SelectVMForPurpose: prefers an explicit kid when provided; falls back to
 * the latest-active selector. The returned VM may be revoked — purpose &
 * timestamp checks are applied by the caller.
 */
import { normalizeVerificationMethodURL } from './resolve-vm-url';
import { isP256PublicMultibase } from './multikey';
import { DIDDocument, VerificationMethodEntry } from './verification-method';

/** The key type a verification method holds, used to pick the signing suite. */
export type KeyKind = 'secp256k1' | 'P-256' | 'RSA';

/** secp256k1: an EC secp256k1 JWK, or a publicKeyHex (EcdsaSecp256k1VerificationKey2019). */
export function vmIsSecp256k1(vm: VerificationMethodEntry | null): boolean {
  if (!vm) return false;
  if (vm.publicKeyJwk) return vm.publicKeyJwk.kty === 'EC' && vm.publicKeyJwk.crv === 'secp256k1';
  return Boolean(vm.publicKeyHex);
}

/** P-256: an EC P-256 JWK, or a P-256 Multikey (publicKeyMultibase). */
export function vmIsP256(vm: VerificationMethodEntry | null): boolean {
  if (!vm) return false;
  if (vm.publicKeyJwk) return vm.publicKeyJwk.kty === 'EC' && vm.publicKeyJwk.crv === 'P-256';
  if (vm.publicKeyMultibase) return isP256PublicMultibase(vm.publicKeyMultibase);
  return false;
}

/** RSA: an RSA JWK. */
export function vmIsRSA(vm: VerificationMethodEntry | null): boolean {
  return Boolean(vm && vm.publicKeyJwk && vm.publicKeyJwk.kty === 'RSA');
}

/** Reports the key kind a verification method holds, or null if unrecognized. */
export function vmKeyKind(vm: VerificationMethodEntry | null): KeyKind | null {
  if (vmIsSecp256k1(vm)) return 'secp256k1';
  if (vmIsP256(vm)) return 'P-256';
  if (vmIsRSA(vm)) return 'RSA';
  return null;
}

function vmMatchesKind(vm: VerificationMethodEntry, kind: KeyKind): boolean {
  if (kind === 'RSA') return vmIsRSA(vm);
  if (kind === 'P-256') return vmIsP256(vm);
  return kind === 'secp256k1' && vmIsSecp256k1(vm);
}

/** When the document has exactly one VM, sign with it; otherwise the latest active VM for purpose. */
export function selectDefaultSigningVM(
  doc: DIDDocument | null,
  purpose: string,
): VerificationMethodEntry {
  if (!doc) throw new Error('did document is nil');
  if (doc.verificationMethod.length === 1) return doc.verificationMethod[0];
  return selectLatestActiveVMForPurpose(doc, purpose);
}

export function ensureVMAuthorizedForPurpose(
  doc: DIDDocument | null,
  vmID: string,
  purpose: string,
): void {
  if (!doc) throw new Error('did document is nil');
  let arr: string[];
  if (purpose === 'authentication') arr = doc.authentication;
  else if (purpose === 'assertionMethod') arr = doc.assertionMethod;
  else throw new Error(`unsupported purpose '${purpose}'`);
  if (!idInPurposeArray(vmID, doc.id, arr)) {
    throw new Error(
      `verification method '${vmID}' is not granted purpose '${purpose}' on DID '${doc.id}'`,
    );
  }
}

export function selectLatestActiveVMForPurpose(
  doc: DIDDocument | null,
  purpose: string,
): VerificationMethodEntry {
  const vm = selectLatestActiveVM(doc, purpose);
  if (!vm) {
    throw new Error(
      `no active verification method for purpose '${purpose}' on DID '${doc!.id}'`,
    );
  }
  return vm;
}

/**
 * Like selectLatestActiveVMForPurpose but only considers VMs holding a key of
 * `kind`, so an RSA signer never binds its proof to a secp256k1 VM (or vice
 * versa) on a DID with keys of several kinds in the same relationship array.
 */
export function selectLatestActiveVMForKey(
  doc: DIDDocument | null,
  purpose: string,
  kind: KeyKind,
): VerificationMethodEntry {
  const vm = selectLatestActiveVM(doc, purpose, (v) => vmMatchesKind(v, kind));
  if (!vm) {
    throw new Error(
      `no active ${kind} verification method for purpose '${purpose}' on DID '${doc!.id}'`,
    );
  }
  return vm;
}

function selectLatestActiveVM(
  doc: DIDDocument | null,
  purpose: string,
  match?: (vm: VerificationMethodEntry) => boolean,
): VerificationMethodEntry | null {
  if (!doc) throw new Error('did document is nil');

  let purposeArr: string[];
  if (purpose === 'authentication') purposeArr = doc.authentication;
  else if (purpose === 'assertionMethod') purposeArr = doc.assertionMethod;
  else throw new Error(`unsupported purpose: ${purpose}`);

  if (!purposeArr || purposeArr.length === 0) {
    throw new Error(
      `no verification methods listed for purpose '${purpose}' on DID '${doc.id}'`,
    );
  }

  let bestVM: VerificationMethodEntry | null = null;
  let bestN = -1;
  for (const vm of doc.verificationMethod) {
    if (vm.revoked) continue;
    if (!idInPurposeArray(vm.id, doc.id, purposeArr)) continue;
    if (match && !match(vm)) continue;
    const n = parseSequentialFragment(vm.id, doc.id) ?? 0;
    // Higher #key-N wins; a tie breaks on the larger id (byte order, like Go)
    // so selection does not depend on the resolver's ordering.
    if (n > bestN || (n === bestN && bestVM && Buffer.compare(Buffer.from(vm.id), Buffer.from(bestVM.id)) > 0)) {
      bestN = n;
      bestVM = vm;
    }
  }
  return bestVM;
}

export function selectVMForPurpose(
  doc: DIDDocument | null,
  purpose: string,
  kid: string,
): VerificationMethodEntry {
  if (!kid) return selectLatestActiveVMForPurpose(doc, purpose);
  if (!doc) throw new Error('did document is nil');

  const canonicalKid = normalizeVerificationMethodURL(doc.id, kid);
  for (const vm of doc.verificationMethod) {
    if (vm.id === canonicalKid) return vm;
  }
  throw new Error(
    `verification method '${kid}' not found in DID '${doc.id}' document`,
  );
}

export function idInPurposeArray(
  vmID: string,
  did: string,
  arr: string[],
): boolean {
  let frag = vmID;
  if (vmID.startsWith(did + '#')) {
    frag = vmID.slice(did.length);
  }
  return arr.some((ref) => ref === vmID || ref === frag);
}

/** N from "<did>#key-N" the way Go's Sscanf("%d") reads it: "#key-02" is 2, "#key-2a" is 2. */
function parseSequentialFragment(vmID: string, did: string): number | null {
  const prefix = `${did}#key-`;
  if (!vmID.startsWith(prefix)) return null;
  const m = /^[ \t]*([+-]?\d+)/.exec(vmID.slice(prefix.length));
  if (!m) return null;
  const big = BigInt(m[1]);
  if (big > 9223372036854775807n || big < -9223372036854775808n) return null;
  return Number(big);
}
