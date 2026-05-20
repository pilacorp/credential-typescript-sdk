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
import { DIDDocument, VerificationMethodEntry } from './verification-method';

export function selectLatestActiveVMForPurpose(
  doc: DIDDocument | null,
  purpose: string,
): VerificationMethodEntry {
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
    const n = parseSequentialFragment(vm.id, doc.id) ?? 0;
    if (n > bestN) {
      bestN = n;
      bestVM = vm;
    }
  }

  if (!bestVM) {
    throw new Error(
      `no active verification method for purpose '${purpose}' on DID '${doc.id}'`,
    );
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

function parseSequentialFragment(vmID: string, did: string): number | null {
  const prefix = `${did}#key-`;
  if (!vmID.startsWith(prefix)) return null;
  const tail = vmID.slice(prefix.length);
  const n = parseInt(tail, 10);
  if (Number.isNaN(n) || String(n) !== tail) return null;
  return n;
}
