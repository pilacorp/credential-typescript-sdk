import type { DIDDocument } from '../../common/verification-method';
import { bytesToHex, hexToBytes, normalizeHex } from '../../common/crypto/hex';
import { generateDIDDocument } from '../document';
import type { SignerProvider } from '../signer';
import { didTypeString, type DIDType, type VerificationMethodSpec } from '../types';
import { parseSubID, subDIDFor, validateSubDID } from './document';
import { setRootConsent, signDocument, signRootConsent, verifyDocumentSignature, verifyRootConsent } from './signature';

export interface SubDIDResult {
  did: string;
  document: DIDDocument;
  type: string;
  signature: string;
}

export type SubDIDOption = (c: { extraVMs: VerificationMethodSpec[] }) => void;

export function withSubDIDVerificationMethods(...specs: VerificationMethodSpec[]): SubDIDOption {
  return (c) => {
    c.extraVMs.push(...specs);
  };
}

export async function generateSubDID(
  rootDID: string,
  subID: string,
  subPublicKeyHex: string,
  didType: DIDType,
  metadata: Record<string, unknown> | null,
  rootSigner: SignerProvider,
  subSigner: SignerProvider,
  ...options: SubDIDOption[]
): Promise<SubDIDResult> {
  if (!rootSigner || !subSigner) throw new Error('subdid: root signer and Sub-DID signer are required');
  if (didTypeString(didType) === 'unknown') throw new Error(`subdid: unknown DID type ${didType}`);
  const cfg = { extraVMs: [] as VerificationMethodSpec[] };
  for (const opt of options) opt(cfg);
  parseSubID(subID);
  const pubBytes = hexToBytes(normalizeHex(subPublicKeyHex));
  if (pubBytes.length !== 33) throw new Error('subdid: Sub-DID public key: expected compressed secp256k1');
  const subDID = subDIDFor(rootDID, subPublicKeyHex);
  const consent = await signRootConsent(subDID, rootSigner);
  const docMetadata: Record<string, unknown> = { ...(metadata ?? {}) };
  docMetadata.subId = subID;
  const doc = generateDIDDocument(subPublicKeyHex, subDID, '', rootDID, didType, docMetadata, cfg.extraVMs);
  if (!doc) throw new Error('subdid: build document: invalid verification methods');
  setRootConsent(doc, consent);
  validateSubDID(doc, rootDID);
  try {
    verifyRootConsent(doc, rootDID);
  } catch (e) {
    throw new Error(`subdid: the root signer does not hold the primary key of ${rootDID}: ${(e as Error).message}`);
  }
  const sig = await signDocument(doc, subSigner);
  try {
    verifyDocumentSignature(doc, sig);
  } catch (e) {
    throw new Error(`subdid: the Sub-DID signer does not hold the key of ${subDID}: ${(e as Error).message}`);
  }
  return {
    did: subDID,
    document: doc,
    type: didTypeString(didType),
    signature: `0x${bytesToHex(sig)}`,
  };
}
