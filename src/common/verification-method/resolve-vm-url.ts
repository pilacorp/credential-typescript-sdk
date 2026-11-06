/**
 * Resolve a VM URL by DID + purpose, and normalize caller-supplied kids.
 * Node port of credential/common/verification-method/resolve_vm_url.go
 */
import { ResolverProvider } from './provider';
import {
  ensureVMAuthorizedForPurpose,
  selectDefaultSigningVM,
  selectLatestActiveVMForKey,
  selectLatestActiveVMForPurpose,
  type KeyKind,
} from './selector';
import { findVerificationMethod } from './vm-lookup';
import type { VerificationMethodEntry } from './verification-method';

export async function resolveVerificationMethodURL(
  did: string,
  purpose: string,
  resolver: ResolverProvider | null,
): Promise<string> {
  if (!resolver) throw new Error('document resolver is not configured');
  const doc = await resolver.resolveDocument(did);
  const vm = selectLatestActiveVMForPurpose(doc, purpose);
  return vm.id;
}

/** Like resolveVerificationMethodURL, but picks the latest active VM whose key is of `kind`. */
export async function resolveVerificationMethodURLForKey(
  did: string,
  purpose: string,
  kind: KeyKind,
  resolver: ResolverProvider | null,
): Promise<string> {
  if (!resolver) throw new Error('document resolver is not configured');
  const doc = await resolver.resolveDocument(did);
  return selectLatestActiveVMForKey(doc, purpose, kind).id;
}

/**
 * Turn a caller-supplied kid into a full "did#fragment" URL. Accepts:
 *  - "did:example:123#key-1"  → returned as-is
 *  - "#key-1"                 → "<did>#key-1"
 *  - "key-1"                  → "<did>#key-1"
 */
export function normalizeVerificationMethodURL(did: string, kid: string): string {
  if (!kid) return '';
  if (kid.startsWith('did:')) return kid;
  if (kid.startsWith('#')) return did + kid;
  return did + '#' + kid;
}

function didFromVMURL(url: string): string {
  if (!url.startsWith('did:')) return '';
  const i = url.indexOf('#');
  return i > 0 ? url.slice(0, i) : url;
}

function rfc3339UTC(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/**
 * Resolve the verification method to sign with: the pinned kid when given,
 * otherwise the default active VM for purpose. Refuses a missing VM, a VM
 * not granted the purpose and a revoked timestamp (like Go, the reason alone is
 * not looked at when signing; verifiers apply the hard-reason rule).
 */
export async function resolveSigningVM(
  did: string,
  purpose: string,
  pinnedKid: string,
  resolver: ResolverProvider | null,
): Promise<{ vm: VerificationMethodEntry; url: string }> {
  if (!resolver) throw new Error('document resolver is not configured');

  const url = normalizeVerificationMethodURL(did, pinnedKid);
  const vmDID = didFromVMURL(url) || did;
  const doc = await resolver.resolveDocument(vmDID);
  const vm = pinnedKid
    ? findVerificationMethod(doc, url)
    : selectDefaultSigningVM(doc, purpose);

  if (vm.revoked) {
    throw new Error(`verification method '${vm.id}' was revoked at ${rfc3339UTC(vm.revoked)}`);
  }
  ensureVMAuthorizedForPurpose(doc, vm.id, purpose);
  return { vm, url: vm.id };
}
