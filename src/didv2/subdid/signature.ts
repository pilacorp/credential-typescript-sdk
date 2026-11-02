import { hashMessage, recoverAddress, hexlify } from 'ethers';
import { secp256k1 } from '@noble/curves/secp256k1';
import type { DIDDocument } from '../../common/verification-method';
import { bytesToHex, hexToBytes } from '../../common/crypto/hex';
import type { SignerProvider } from '../signer';
import { checkDID, didAddress, docHash } from './document';

export const rootConsentPrefix = 'Sub-DID ';
const rootConsentKey = 'rootConsent';
const signatureLength = 65;
const storedSignaturePattern = /^0x[0-9a-f]{130}$/;

export const ErrConsentInvalid = new Error('subdid: root consent invalid');
export const ErrPossessionInvalid = new Error('subdid: sub-DID signature invalid');

export function normalizeSignature(sig: Uint8Array): Uint8Array {
  if (sig.length !== signatureLength) {
    throw new Error(`subdid: signature is ${sig.length} bytes, want ${signatureLength}`);
  }
  const out = new Uint8Array(sig);
  switch (out[64]) {
    case 0:
    case 1:
      out[64] = out[64] + 27;
      break;
    case 27:
    case 28:
      break;
    default:
      throw new Error(`subdid: signature v = ${out[64]}, want 0, 1, 27 or 28`);
  }
  const halfN = secp256k1.CURVE.n >> 1n;
  const s = BigInt(`0x${bytesToHex(out.slice(32, 64))}`);
  if (s > halfN) throw new Error('subdid: signature s is above n/2');
  return out;
}

export function rootConsentDigest(subDID: string): Uint8Array {
  return hexToBytes(hashMessage(rootConsentPrefix + subDID));
}

export async function signRootConsent(subDID: string, root: SignerProvider): Promise<Uint8Array> {
  checkDID(subDID);
  if (!root) throw new Error('subdid: root signer is nil');
  const digest = rootConsentDigest(subDID);
  const sig = await root.sign(digest);
  return normalizeSignature(sig instanceof Uint8Array ? sig : new Uint8Array(sig));
}

export function setRootConsent(doc: DIDDocument, sig: Uint8Array): void {
  if (!doc) throw new Error('subdid: document is nil');
  const normalized = normalizeSignature(sig);
  const meta = { ...(doc.didDocumentMetadata ?? {}) };
  meta[rootConsentKey] = `0x${bytesToHex(normalized)}`;
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(meta).sort()) sorted[key] = meta[key];
  doc.didDocumentMetadata = sorted;
}

export function getRootConsent(doc: DIDDocument | null | undefined): Uint8Array {
  if (!doc) throw wrap(ErrConsentInvalid, 'document is nil');
  const value = doc.didDocumentMetadata?.[rootConsentKey];
  if (value === undefined) throw wrap(ErrConsentInvalid, 'rootConsent is missing');
  if (typeof value !== 'string' || !storedSignaturePattern.test(value)) {
    throw wrap(ErrConsentInvalid, 'rootConsent must be 0x followed by 130 lowercase hex characters');
  }
  const sig = hexToBytes(value);
  if (sig[64] !== 27 && sig[64] !== 28) {
    throw wrap(ErrConsentInvalid, `rootConsent v = ${sig[64]}, want 27 or 28`);
  }
  normalizeSignature(sig);
  return sig;
}

export function verifyRootConsent(subDoc: DIDDocument, rootDID: string): void {
  const sig = getRootConsent(subDoc);
  try {
    checkDID(rootDID);
  } catch (e) {
    throw wrap(ErrConsentInvalid, `root DID: ${(e as Error).message}`);
  }
  try {
    checkDID(subDoc.id);
  } catch (e) {
    throw wrap(ErrConsentInvalid, `Sub-DID: ${(e as Error).message}`);
  }
  try {
    checkSigner(rootConsentDigest(subDoc.id), sig, didAddress(rootDID));
  } catch (e) {
    throw wrap(ErrConsentInvalid, (e as Error).message);
  }
}

export function signatureDigest(documentHash: string): Uint8Array {
  return hexToBytes(hashMessage(hexToBytes(documentHash)));
}

export async function signDocument(doc: DIDDocument, sub: SignerProvider): Promise<Uint8Array> {
  if (!sub) throw new Error('subdid: Sub-DID signer is nil');
  const h = docHash(doc);
  const sig = await sub.sign(signatureDigest(h));
  return normalizeSignature(sig instanceof Uint8Array ? sig : new Uint8Array(sig));
}

export function verifyDocumentSignature(doc: DIDDocument | null | undefined, sig: Uint8Array): void {
  let normalized: Uint8Array;
  try {
    normalized = normalizeSignature(sig);
  } catch (e) {
    throw wrap(ErrPossessionInvalid, (e as Error).message);
  }
  if (!doc) throw wrap(ErrPossessionInvalid, 'document is nil');
  let h: string;
  try {
    h = docHash(doc);
  } catch (e) {
    throw wrap(ErrPossessionInvalid, (e as Error).message);
  }
  try {
    checkSigner(signatureDigest(h), normalized, didAddress(doc.id));
  } catch (e) {
    throw wrap(ErrPossessionInvalid, (e as Error).message);
  }
}

function checkSigner(digest: Uint8Array, storedSig: Uint8Array, address: string): void {
  const recovered = recoverAddress(hexlify(digest), hexlify(storedSig)).toLowerCase();
  if (recovered !== address.toLowerCase()) {
    throw new Error(`signed by ${recovered}, not by ${address}`);
  }
}

function wrap(base: Error, detail: string): Error {
  return new Error(`${base.message}: ${detail}`);
}
