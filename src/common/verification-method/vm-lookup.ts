/**
 * VM lookup helpers — Node port of
 * credential/common/verification-method/vm_lookup.go
 */
import { DIDDocument, VerificationMethodEntry } from './verification-method';

export function didFromVerificationMethodURL(vmURL: string): string {
  if (!vmURL) throw new Error('verification method is empty');
  const idx = vmURL.indexOf('#');
  if (idx < 0) {
    throw new Error(
      `invalid verification method URL, could not extract DID: ${vmURL}`,
    );
  }
  const didPart = vmURL.slice(0, idx);
  if (!didPart) {
    throw new Error(
      `invalid verification method URL, could not extract DID: ${vmURL}`,
    );
  }
  if (!didPart.startsWith('did:')) {
    throw new Error(
      `extracted DID '${didPart}' is invalid, must start with 'did:'`,
    );
  }
  return didPart;
}

export function findVerificationMethod(
  doc: DIDDocument | null,
  vmURL: string,
): VerificationMethodEntry {
  if (!doc) throw new Error('did document is nil');
  if (!vmURL) throw new Error('verification method is empty');

  for (const vm of doc.verificationMethod) {
    if (vm.id === vmURL) return vm;
  }
  throw new Error(
    `verification method '${vmURL}' not found in DID '${doc.id}' document`,
  );
}
