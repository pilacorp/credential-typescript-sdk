import { createHash, randomBytes } from 'node:crypto';
import { p256 } from '@noble/curves/nist';
import { sha256 } from '@noble/hashes/sha256';
import type { SignerProvider } from '../signer/signer';
import { P256Provider } from '../signer/p256-provider';
import {
  canonicalizeNQuadsWithIdMap,
  canonicalizeRDF,
} from '../processor/processor';
import {
  encodeP256PublicMultikeyBytes,
  decodeP256PublicMultikeyBytes,
} from '../verification-method/multikey';
import {
  canonicalizeAndGroup,
  hashMandatory,
  orderedValues,
  relabelBlankNodes,
  sortedIndexes,
} from './group';
import { selectJsonLd } from './pointer';
import {
  baseProofHeader,
  derivedProofHeader,
  decodeProofValue,
  parseBaseProofValue,
  parseDisclosureProofValue,
  serializeBaseProofValue,
  serializeDisclosureProofValue,
} from './proofvalue';

export const Cryptosuite = 'ecdsa-sd-2023';

function hashProofConfig(proofConfig: Record<string, unknown>): Promise<Uint8Array> {
  return canonicalizeRDF(proofConfig).then((nquads) => sha256(nquads));
}

function signStatement(priv: Uint8Array, statement: string): Uint8Array {
  const digest = sha256(Buffer.from(statement, 'utf8'));
  const sig = p256.sign(digest, priv, { lowS: true });
  return sig.toCompactRawBytes();
}

function verifyP256(pubUncompressed: Uint8Array, digest: Uint8Array, signature: Uint8Array): boolean {
  try {
    return p256.verify(signature, digest, pubUncompressed, { lowS: false });
  } catch {
    return false;
  }
}

export async function createBaseProof(
  document: Record<string, unknown>,
  proofConfig: Record<string, unknown>,
  mandatoryPointers: string[],
  issuerSigner: SignerProvider,
  issuerPub?: Uint8Array,
): Promise<string> {
  const proofHash = await hashProofConfig(proofConfig);
  const hmacKey = randomBytes(32);
  const grouped = await canonicalizeAndGroup(document, hmacKey, {
    mandatory: mandatoryPointers,
  });
  const mg = grouped.groups.mandatory;
  const nonMandatory = orderedValues(mg.nonMatching);
  const mandatoryHash = hashMandatory(mg.matching);
  const ephPriv = p256.utils.randomPrivateKey();
  const ephPub = encodeP256PublicMultikeyBytes(p256.getPublicKey(ephPriv, false));
  const signatures = nonMandatory.map((nq) => signStatement(ephPriv, nq));
  const toSign = new Uint8Array(proofHash.length + ephPub.length + mandatoryHash.length);
  toSign.set(proofHash, 0);
  toSign.set(ephPub, proofHash.length);
  toSign.set(mandatoryHash, proofHash.length + ephPub.length);
  const digest = sha256(toSign);
  const baseSig = await issuerSigner.sign(digest);
  if (issuerPub) {
    const ok =
      issuerSigner instanceof P256Provider
        ? verifyP256(issuerPub, digest, baseSig)
        : true;
    if (issuerSigner instanceof P256Provider && !ok) {
      throw new Error(
        'ecdsasd: the base signature does not verify against the verification method; the signer does not hold that key',
      );
    }
  }
  return serializeBaseProofValue({
    baseSignature: baseSig,
    publicKey: ephPub,
    hmacKey,
    signatures,
    mandatoryPointers,
  });
}

export async function deriveProof(
  document: Record<string, unknown>,
  baseProofValue: string,
  selectivePointers: string[],
): Promise<{ revealDoc: Record<string, unknown>; proofValue: string }> {
  const bp = parseBaseProofValue(baseProofValue);
  const combined = [...bp.mandatoryPointers, ...selectivePointers];
  const grouped = await canonicalizeAndGroup(document, bp.hmacKey, {
    mandatory: bp.mandatoryPointers,
    selective: selectivePointers,
    combined,
  });
  const mandatoryGroup = grouped.groups.mandatory;
  const selectiveGroup = grouped.groups.selective;
  const combinedGroup = grouped.groups.combined;
  const mandatoryIndexes: number[] = [];
  sortedIndexes(combinedGroup.matching).forEach((abs, rel) => {
    if (mandatoryGroup.matching.has(abs)) mandatoryIndexes.push(rel);
  });
  const filtered: Uint8Array[] = [];
  let index = 0;
  for (const sig of bp.signatures) {
    while (mandatoryGroup.matching.has(index)) index += 1;
    if (selectiveGroup.matching.has(index)) filtered.push(sig);
    index += 1;
  }
  const revealDoc = selectJsonLd(document, combined);
  if (!revealDoc) {
    throw new Error('ecdsasd: no statements to reveal; provide mandatory or selective pointers');
  }
  const [, rawIDMap] = await canonicalizeNQuadsWithIdMap(combinedGroup.deskolemizedNQuads);
  const verifierLabelMap: Record<string, string> = {};
  for (const [inputLabel, c14n] of rawIDMap.entries()) {
    const inn = inputLabel.replace(/^_:/, '');
    const verifier = c14n.replace(/^_:/, '');
    verifierLabelMap[verifier] = grouped.labelMap[inn];
  }
  const proofValue = serializeDisclosureProofValue({
    baseSignature: bp.baseSignature,
    publicKey: bp.publicKey,
    signatures: filtered,
    labelMap: verifierLabelMap,
    mandatoryIndexes,
  });
  return { revealDoc, proofValue };
}

async function verifyBaseProof(
  document: Record<string, unknown>,
  proofConfig: Record<string, unknown>,
  baseProofValue: string,
  issuerPub: Uint8Array,
): Promise<void> {
  const bp = parseBaseProofValue(baseProofValue);
  const ephPub = decodeP256PublicMultikeyBytes(bp.publicKey);
  const grouped = await canonicalizeAndGroup(document, bp.hmacKey, {
    mandatory: bp.mandatoryPointers,
  });
  const mg = grouped.groups.mandatory;
  const nonMandatory = orderedValues(mg.nonMatching);
  const mandatoryHash = hashMandatory(mg.matching);
  const proofHash = await hashProofConfig(proofConfig);
  const signData = new Uint8Array(proofHash.length + bp.publicKey.length + mandatoryHash.length);
  signData.set(proofHash, 0);
  signData.set(bp.publicKey, proofHash.length);
  signData.set(mandatoryHash, proofHash.length + bp.publicKey.length);
  const digest = sha256(signData);
  if (!verifyIssuer(issuerPub, digest, bp.baseSignature)) {
    throw new Error('ecdsasd: issuer base signature invalid');
  }
  if (bp.signatures.length !== nonMandatory.length) {
    throw new Error(
      `ecdsasd: signature count ${bp.signatures.length} != non-mandatory quads ${nonMandatory.length}`,
    );
  }
  nonMandatory.forEach((nq, i) => {
    const d = sha256(Buffer.from(nq, 'utf8'));
    if (!verifyP256(ephPub, d, bp.signatures[i])) {
      throw new Error(`ecdsasd: non-mandatory statement signature invalid: ${nq}`);
    }
  });
}

async function verifyDerivedProof(
  revealDoc: Record<string, unknown>,
  proofConfig: Record<string, unknown>,
  derivedProofValue: string,
  issuerPub: Uint8Array,
): Promise<void> {
  const dp = parseDisclosureProofValue(derivedProofValue);
  const ephPub = decodeP256PublicMultikeyBytes(dp.publicKey);
  const { canonicalizeWithIdMap } = await import('../processor/processor');
  const [canonicalNQuads] = await canonicalizeWithIdMap(revealDoc);
  const relabeled = relabelBlankNodes(canonicalNQuads, dp.labelMap);
  relabeled.sort();
  const mandatorySet = new Set(dp.mandatoryIndexes);
  const mandatory: string[] = [];
  const nonMandatory: string[] = [];
  relabeled.forEach((nq, i) => {
    if (mandatorySet.has(i)) mandatory.push(nq);
    else nonMandatory.push(nq);
  });
  const proofHash = await hashProofConfig(proofConfig);
  const mb = Buffer.concat(mandatory.map((nq) => Buffer.from(nq, 'utf8')));
  const mandatoryHash = new Uint8Array(createHash('sha256').update(mb).digest());
  const signData = new Uint8Array(proofHash.length + dp.publicKey.length + mandatoryHash.length);
  signData.set(proofHash, 0);
  signData.set(dp.publicKey, proofHash.length);
  signData.set(mandatoryHash, proofHash.length + dp.publicKey.length);
  if (!verifyIssuer(issuerPub, sha256(signData), dp.baseSignature)) {
    throw new Error('ecdsasd: issuer base signature invalid');
  }
  if (dp.signatures.length !== nonMandatory.length) {
    throw new Error(
      `ecdsasd: signature count ${dp.signatures.length} != non-mandatory quads ${nonMandatory.length}`,
    );
  }
  nonMandatory.forEach((nq, i) => {
    const d = sha256(Buffer.from(nq, 'utf8'));
    if (!verifyP256(ephPub, d, dp.signatures[i])) {
      throw new Error(`ecdsasd: non-mandatory statement signature invalid: ${nq}`);
    }
  });
}

function verifyIssuer(pub: Uint8Array, digest: Uint8Array, signature: Uint8Array): boolean {
  if (verifyP256(pub, digest, signature)) return true;
  try {
    const { secp256k1 } = require('@noble/curves/secp256k1');
    return secp256k1.verify(signature.subarray(0, 64), digest, pub, { lowS: false });
  } catch {
    return false;
  }
}

export async function verifyProof(
  document: Record<string, unknown>,
  proofConfig: Record<string, unknown>,
  proofValue: string,
  issuerPub: Uint8Array,
): Promise<void> {
  try {
    decodeProofValue(proofValue, baseProofHeader);
    return verifyBaseProof(document, proofConfig, proofValue, issuerPub);
  } catch {
    /* try derived */
  }
  try {
    decodeProofValue(proofValue, derivedProofHeader);
    return verifyDerivedProof(document, proofConfig, proofValue, issuerPub);
  } catch (err) {
    if ((err as Error).message?.startsWith('ecdsasd: issuer') || (err as Error).message?.includes('statement')) {
      throw err;
    }
    throw new Error('ecdsasd: unrecognized proof value header');
  }
}

export const CreateBaseProof = createBaseProof;
export const DeriveProof = deriveProof;
export const VerifyProof = verifyProof;
