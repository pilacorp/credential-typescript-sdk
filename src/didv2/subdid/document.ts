import type { DIDDocument } from '../../common/verification-method';
import { hexToBytes, normalizeHex } from '../../common/crypto/hex';
import {
  addressFromPublicKeyHex,
  findVerificationMethod,
  hashDIDDocument,
  validateDIDDocument,
} from '../document';

const primaryKeyFragment = '#key-1';
const secp256k1VMType = 'EcdsaSecp256k1VerificationKey2019';
export const subIDKey = 'subId';

const subIDPattern = /^[A-Za-z0-9_-]{8,64}$/;
const didPattern = /^did:[a-z]{1,16}(:[a-z]{1,16}){0,2}:0x[0-9a-f]{40}$/;
const compressedKeyPattern = /^0x0[23][0-9a-f]{64}$/;

export function parseSubID(s: string): string {
  if (!subIDPattern.test(s)) throw new Error(`subdid: subId must match ${subIDPattern}`);
  return s;
}

export function subDIDFor(rootDID: string, publicKeyHex: string): string {
  const bytes = hexToBytes(normalizeHex(publicKeyHex));
  if (!(bytes.length === 33 && (bytes[0] === 0x02 || bytes[0] === 0x03))) {
    throw new Error('subdid: public key must be a point on secp256k1');
  }
  checkDID(rootDID);
  const addr = addressFromPublicKeyHex(publicKeyHex);
  return `${didPrefix(rootDID)}${addr}`;
}

export function validateSubDID(doc: DIDDocument | null | undefined, rootDID: string): void {
  if (!doc) throw new Error('subdid: document is nil');
  validateDIDDocument(doc);
  checkDID(doc.id);
  checkDID(rootDID);
  if (didPrefix(doc.id) !== didPrefix(rootDID)) {
    throw new Error(`subdid: ${doc.id} and root ${rootDID} have different prefixes`);
  }
  if (doc.id === rootDID) throw new Error('subdid: a Sub-DID cannot be its own root');
  if (doc.controller !== rootDID) {
    throw new Error(`subdid: controller ${JSON.stringify(doc.controller)} is not the root DID ${rootDID}`);
  }
  for (const vm of doc.verificationMethod) {
    if (!vm.id.startsWith(`${doc.id}#`)) {
      throw new Error(`subdid: verification method id ${JSON.stringify(vm.id)} must start with ${doc.id}#`);
    }
  }
  checkPrimaryKey(doc);
  if (!doc.didDocumentMetadata) throw new Error('subdid: didDocumentMetadata is missing');
}

function checkPrimaryKey(doc: DIDDocument): void {
  const vm = findVerificationMethod(doc, primaryKeyFragment);
  if (!vm) throw new Error('subdid: #key-1 is missing');
  if (vm.type !== secp256k1VMType) {
    throw new Error(`subdid: #key-1 has type ${JSON.stringify(vm.type)}, want ${secp256k1VMType}`);
  }
  if (!vm.publicKeyHex || !compressedKeyPattern.test(vm.publicKeyHex)) {
    throw new Error('subdid: #key-1 publicKeyHex must be a lowercase compressed secp256k1 key');
  }
  const address = addressFromPublicKeyHex(vm.publicKeyHex);
  if (address !== didAddress(doc.id)) {
    throw new Error(`subdid: #key-1 belongs to ${address}, not to ${doc.id}`);
  }
}

export function checkDID(s: string): void {
  if (!didPattern.test(s)) throw new Error(`${JSON.stringify(s)} does not match ${didPattern}`);
}

export function didPrefix(s: string): string {
  return s.slice(0, s.lastIndexOf(':') + 1);
}

export function didAddress(s: string): string {
  return s.slice(s.lastIndexOf(':') + 1);
}

export function docHash(doc: DIDDocument): string {
  const h = hashDIDDocument(doc);
  if (!/^0x[0-9a-f]{64}$/.test(h)) throw new Error(`subdid: document hash ${JSON.stringify(h)} is not 32 bytes`);
  return h;
}
