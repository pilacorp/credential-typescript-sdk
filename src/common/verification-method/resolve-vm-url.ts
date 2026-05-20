/**
 * Resolve a VM URL by DID + purpose, and normalize caller-supplied kids.
 * Node port of credential/common/verification-method/resolve_vm_url.go
 */
import { ResolverProvider } from './provider';
import { selectLatestActiveVMForPurpose } from './selector';

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
