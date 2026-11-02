/**
 * Embedded JSON-LD proof helpers — Node port of credential/common/jsonmap/jsonmap.go
 *
 * Provides:
 *  - Canonicalize: URDNA2015 normalization + sha256 digest of a JSONMap
 *    (with `proof` excluded), which is the input signed by ECDSA-RDFC-2019.
 *  - AddECDSAProof / AddCustomProof: attach a DataIntegrityProof or
 *    caller-supplied proof.
 *  - VerifyProof: dispatch JwtProof2020 / DataIntegrityProof / legacy ECDSA
 *    with strict purpose & revocation checks.
 */
import { p256 } from '@noble/curves/nist';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { ecdsaVerifySignature, verifyJSONSignature } from '../crypto/crypto';
import { hashForJWSAlg, p256PubFromJwk, verifyES256, verifyRSAJWS } from '../crypto/jws-2020';
import { bytesToHex, hexToBytes, keyToBytes } from '../crypto/hex';
import { verifyJwtProof } from '../crypto/jwt-proof-2020';
import { canonicalizeDocument, computeDigest } from '../processor/processor';
import { createBaseProof, deriveProof, verifyProof as verifyEcdsaSd } from '../ecdsasd';
import { P256Provider } from '../signer/p256-provider';
import { SignerProvider, validateSignatureLength } from '../signer/signer';
import type { Proof } from '../dto/proof';
import { decodeBase58Btc, encodeBase58Btc } from '../util/multibase';
import {
  DIDDocument,
  findVerificationMethod,
  isHardRevocationReason,
  publicKeyHexFromVM,
  ResolverProvider,
  VerificationMethodEntry,
} from '../verification-method';
import { serializeProofs } from '../util/vc';
import { JSONMap } from '../util/json';
import { formatRFC3339 } from '../util/time';

const PROOF_FIELD = 'proof';

export const JwtProof2020 = 'JwtProof2020';
export const EcdsaSecp256k1Signature2019 = 'EcdsaSecp256k1Signature2019';
export const DataIntegrityProof = 'DataIntegrityProof';
export const ECDSARDFC2019 = 'ecdsa-rdfc-2019';
export const ECDSASD2023 = 'ecdsa-sd-2023';
export const ECDSASECPKEY = 'EcdsaSecp256k1VerificationKey2019';
export const JsonWebSignature2020 = 'JsonWebSignature2020';
export const JsonWebKey2020 = 'JsonWebKey2020';
const DATA_INTEGRITY_V2_CONTEXT = 'https://w3id.org/security/data-integrity/v2';

export function toJSON(m: JSONMap): Uint8Array {
  return new Uint8Array(Buffer.from(JSON.stringify(m), 'utf8'));
}

export function toMap(m: JSONMap): JSONMap {
  return JSON.parse(JSON.stringify(m)) as JSONMap;
}

/**
 * Canonicalize the JSONMap (excluding `proof`) and return its sha256 digest.
 * This is the byte string the ECDSA-RDFC-2019 cryptosuite signs.
 */
export async function canonicalize(m: JSONMap): Promise<Uint8Array> {
  const mCopy: JSONMap = {};
  for (const [k, v] of Object.entries(m)) {
    if (k !== PROOF_FIELD) mCopy[k] = v;
  }
  const canonical = await canonicalizeDocument(mCopy);
  return computeDigest(canonical);
}

export async function addECDSAProof(
  m: JSONMap,
  signer: SignerProvider,
  verificationMethod: string,
  proofPurpose: string,
  extras: { challenge?: string; domain?: string } = {},
): Promise<void> {
  if (!m) throw new Error('jsonmap: JSONMap is nil');
  if (!signer) throw new Error('jsonmap: signer provider cannot be nil');
  if (!verificationMethod) throw new Error('jsonmap: verification method is required');
  if (!proofPurpose) throw new Error('jsonmap: proof purpose is required');

  const proof: Proof = {
    type: DataIntegrityProof,
    created: formatRFC3339(new Date()),
    verificationMethod,
    proofPurpose,
    cryptosuite: ECDSARDFC2019,
  };
  if (extras.challenge) proof.challenge = extras.challenge;
  if (extras.domain) proof.domain = extras.domain;

  if (signer instanceof P256Provider) {
    ensureDataIntegrityContext(m);
    const hashData = await ecdsaHashData(m, proof);
    const digest = sha256(hashData);
    const signature = await signer.sign(digest);
    if (signature.length !== 64) {
      throw new Error(
        `jsonmap: ecdsa-rdfc-2019 expects a 64-byte P-256 signature (r||s) but the signer returned ${signature.length} bytes`,
      );
    }
    proof.proofValue = encodeBase58Btc(signature);
    m[PROOF_FIELD] = serializeProofs([proof]);
    return;
  }

  const signData = await canonicalize(m);
  if (signData.length !== 32) {
    throw new Error(
      `jsonmap: invalid signing digest length: got ${signData.length}, want 32`,
    );
  }
  const signature = await signer.sign(signData);
  validateSignatureLength(signature);
  proof.proofValue = bytesToHex(signature);

  m[PROOF_FIELD] = serializeProofs([proof]);
}

export async function ecdsaHashData(m: JSONMap, proof: Proof): Promise<Uint8Array> {
  const docHash = await canonicalize(m);
  return proofHashData(m, docHash, proof);
}

export async function proofHashData(
  m: JSONMap,
  docHash: Uint8Array,
  proof: Proof,
): Promise<Uint8Array> {
  if (docHash.length !== 32) {
    throw new Error(`document digest must be 32 bytes, got ${docHash.length}`);
  }
  const ctx = m['@context'];
  if (ctx === undefined || ctx === null) {
    throw new Error('document is missing the @context needed to canonicalize the proof configuration');
  }
  const cfg: JSONMap = {
    type: proof.type,
    created: proof.created,
    verificationMethod: proof.verificationMethod,
    proofPurpose: proof.proofPurpose,
    '@context': ctx,
  };
  if (proof.cryptosuite) cfg.cryptosuite = proof.cryptosuite;
  if (proof.challenge) cfg.challenge = proof.challenge;
  if (proof.domain) cfg.domain = proof.domain;
  const cfgCanonical = await canonicalizeDocument(cfg);
  const cfgHash = computeDigest(cfgCanonical);
  const hashData = new Uint8Array(64);
  hashData.set(cfgHash, 0);
  hashData.set(docHash, 32);
  return hashData;
}

function ensureDataIntegrityContext(m: JSONMap): void {
  const ctx = m['@context'];
  if (ctx === undefined || ctx === null) {
    m['@context'] = [DATA_INTEGRITY_V2_CONTEXT];
    return;
  }
  if (typeof ctx === 'string') {
    if (!coversDataIntegrity(ctx)) m['@context'] = [ctx, DATA_INTEGRITY_V2_CONTEXT];
    return;
  }
  if (Array.isArray(ctx)) {
    if (ctx.some((e) => typeof e === 'string' && coversDataIntegrity(e))) return;
    m['@context'] = [...ctx, DATA_INTEGRITY_V2_CONTEXT];
  }
}

function coversDataIntegrity(ctx: string): boolean {
  return (
    ctx.includes('data-integrity') ||
    ctx.includes('/ns/credentials/v2') ||
    ctx.includes('credentials/v2')
  );
}

export async function addECDSASDBaseProof(
  m: JSONMap,
  signerProvider: SignerProvider,
  verificationMethod: string,
  proofPurpose: string,
  mandatoryPointers: string[],
  issuerPub?: Uint8Array,
): Promise<void> {
  if (!m) throw new Error('jsonmap: JSONMap is nil');
  if (!signerProvider) throw new Error('jsonmap: signer provider cannot be nil');
  if (!verificationMethod) throw new Error('jsonmap: verification method is required');
  if (!proofPurpose) throw new Error('jsonmap: proof purpose is required');
  if (m[PROOF_FIELD]) {
    throw new Error(
      'jsonmap: the document already carries a proof; an ecdsa-sd-2023 base proof replaces the proof set, so remove the existing proof first if that is intended',
    );
  }
  ensureDataIntegrityContext(m);
  const proof: Proof = {
    type: DataIntegrityProof,
    cryptosuite: ECDSASD2023,
    created: formatRFC3339(new Date()),
    verificationMethod,
    proofPurpose,
  };
  const docNoProof: JSONMap = {};
  for (const [k, v] of Object.entries(m)) {
    if (k !== PROOF_FIELD) docNoProof[k] = v;
  }
  proof.proofValue = await createBaseProof(
    docNoProof,
    ecdsaProofConfig(m, proof),
    mandatoryPointers,
    signerProvider,
    issuerPub,
  );
  m[PROOF_FIELD] = serializeProofs([proof]);
}

export async function deriveECDSASD(m: JSONMap, selectivePointers: string[]): Promise<JSONMap> {
  if (!m) throw new Error('jsonmap: JSONMap is nil');
  const baseProof = parseRawToProof(getFirstProof(m));
  if (baseProof.type !== DataIntegrityProof || baseProof.cryptosuite !== ECDSASD2023 || !baseProof.proofValue) {
    throw new Error('jsonmap: credential has no ecdsa-sd-2023 proof to derive from');
  }
  const docNoProof: JSONMap = {};
  for (const [k, v] of Object.entries(m)) {
    if (k !== PROOF_FIELD) docNoProof[k] = v;
  }
  const { revealDoc, proofValue } = await deriveProof(docNoProof, baseProof.proofValue, selectivePointers);
  const derived: JSONMap = { ...revealDoc };
  derived[PROOF_FIELD] = serializeProofs([{ ...baseProof, proofValue }]);
  return derived;
}

function ecdsaProofConfig(m: JSONMap, proof: Proof): JSONMap {
  const ctx = m['@context'];
  if (ctx === undefined || ctx === null) {
    throw new Error('document is missing the @context needed to canonicalize the proof configuration');
  }
  const cfg: JSONMap = {
    type: proof.type,
    created: proof.created,
    verificationMethod: proof.verificationMethod,
    proofPurpose: proof.proofPurpose,
    '@context': ctx,
  };
  if (proof.cryptosuite) cfg.cryptosuite = proof.cryptosuite;
  if (proof.challenge) cfg.challenge = proof.challenge;
  if (proof.domain) cfg.domain = proof.domain;
  return cfg;
}

async function verifyECDSASDProof(m: JSONMap, doc: DIDDocument, proof: Proof): Promise<boolean> {
  const vm = findVerificationMethod(doc, proof.verificationMethod);
  const publicKey = publicKeyHexFromVM(vm);
  const docNoProof: JSONMap = {};
  for (const [k, v] of Object.entries(m)) {
    if (k !== PROOF_FIELD) docNoProof[k] = v;
  }
  await verifyEcdsaSd(docNoProof, ecdsaProofConfig(m, proof), proof.proofValue ?? '', hexToBytes(publicKey));
  strictPurposeCheck(doc, vm, proof.proofPurpose, proof.created);
  return true;
}

export function addCustomProof(m: JSONMap, proof: Proof | null): void {
  if (!m) throw new Error('JSONMap is nil');
  if (!proof) throw new Error('proof is nil');
  m[PROOF_FIELD] = serializeProofs([proof]);
}

export async function verifyProof(
  m: JSONMap,
  resolver: ResolverProvider | null,
): Promise<boolean> {
  if (!m) throw new Error('JSONMap is nil');
  if (!resolver) throw new Error('document resolver is required');

  const proof = parseRawToProof(getFirstProof(m));
  const signerDID = signerDIDFromBody(m);
  const doc = await resolver.resolveDocument(signerDID);

  if (proof.type === JwtProof2020) {
    return verifyJWTProofImpl(m, doc, proof);
  }
  if (
    proof.type === EcdsaSecp256k1Signature2019 ||
    proof.type === ECDSASECPKEY
  ) {
    return verifyEcdsaProofLegacy(m);
  }
  if (proof.type === DataIntegrityProof && proof.cryptosuite === ECDSARDFC2019) {
    return verifyDataIntegrityProof(m, doc, proof);
  }
  if (proof.type === DataIntegrityProof && proof.cryptosuite === ECDSASD2023) {
    return verifyECDSASDProof(m, doc, proof);
  }
  if (proof.type === JsonWebSignature2020) {
    return verifyJWSProof(m, doc, proof);
  }
  throw new Error(`unsupported proof type: ${proof.type}`);
}

async function verifyJWSProof(m: JSONMap, doc: DIDDocument, proof: Proof): Promise<boolean> {
  const vm = findVerificationMethod(doc, proof.verificationMethod);
  if (vm.type !== JsonWebKey2020) {
    throw new Error(`expected ${JsonWebKey2020} VM, got ${vm.type}`);
  }
  if (!vm.publicKeyJwk) {
    throw new Error(`verification method '${vm.id}' has no publicKeyJwk`);
  }
  const split = splitDetachedJWS(proof.jws ?? '');
  if (!split) throw new Error('malformed detached JWS');
  const alg = detachedJWSAlg(split.header);
  const payload = await canonicalize(m);
  const signingInput = Buffer.concat([
    Buffer.from(split.header, 'utf8'),
    Buffer.from('.', 'utf8'),
    Buffer.from(payload),
  ]);
  const sig = Buffer.from(split.sig, 'base64url');
  if (alg === 'ES256') {
    const pub = p256PubFromJwk(vm.publicKeyJwk);
    const digest = hashForJWSAlg(alg, new Uint8Array(signingInput));
    if (!verifyES256(pub, digest, new Uint8Array(sig))) {
      throw new Error('JsonWebSignature2020 ES256 signature verification failed');
    }
  } else if (
    alg === 'RS256' ||
    alg === 'RS384' ||
    alg === 'RS512' ||
    alg === 'PS256' ||
    alg === 'PS384' ||
    alg === 'PS512'
  ) {
    verifyRSAJWS(alg, vm.publicKeyJwk, new Uint8Array(signingInput), new Uint8Array(sig));
  } else {
    throw new Error(`unsupported JsonWebSignature2020 alg: ${JSON.stringify(alg)}`);
  }
  strictPurposeCheck(doc, vm, proof.proofPurpose, proof.created);
  return true;
}

function splitDetachedJWS(jws: string): { header: string; sig: string } | null {
  const idx = jws.indexOf('..');
  if (idx <= 0) return null;
  const header = jws.slice(0, idx);
  const sig = jws.slice(idx + 2);
  if (!header || !sig) return null;
  return { header, sig };
}

function detachedJWSAlg(encHeader: string): string {
  const hdr = JSON.parse(Buffer.from(encHeader, 'base64url').toString('utf8')) as {
    alg?: string;
    b64?: unknown;
    crit?: string[];
  };
  if (hdr.b64 !== false) throw new Error('jws header b64 must be false');
  if (!Array.isArray(hdr.crit) || !hdr.crit.includes('b64')) {
    throw new Error('jws header crit must include b64');
  }
  if (!hdr.alg) throw new Error('jws header missing alg');
  return hdr.alg;
}

async function verifyJWTProofImpl(
  m: JSONMap,
  doc: DIDDocument,
  proof: Proof,
): Promise<boolean> {
  const vmURL = jwtVerificationMethodURL(m);
  const vm = findVerificationMethod(doc, vmURL);
  const publicKey = publicKeyHexFromVM(vm);

  const ok = verifyJwtProof(m, publicKey);
  if (!ok) return false;
  strictPurposeCheck(doc, vm, 'assertionMethod', proof.created);
  return true;
}

async function verifyDataIntegrityProof(
  m: JSONMap,
  doc: DIDDocument,
  proof: Proof,
): Promise<boolean> {
  const vm = findVerificationMethod(doc, proof.verificationMethod);
  const publicKey = publicKeyHexFromVM(vm);

  if (!proof.proofValue) return false;
  let ok: boolean;
  if (proof.proofValue.startsWith('z')) {
    const signature = decodeBase58Btc(proof.proofValue);
    if (signature.length !== 64) {
      throw new Error(
        `ecdsa-rdfc-2019 proofValue decodes to ${signature.length} bytes, want 64 (r||s)`,
      );
    }
    const hashData = await ecdsaHashData(m, proof);
    const digest = sha256(hashData);
    ok = verifyRawEcdsa(publicKey, digest, signature);
  } else {
    const digest = await canonicalize(m);
    ok = ecdsaVerifySignature(publicKey, proof.proofValue, digest);
  }
  if (!ok) return false;
  strictPurposeCheck(doc, vm, proof.proofPurpose, proof.created);
  return true;
}

function verifyRawEcdsa(publicKeyHex: string, digest: Uint8Array, signature: Uint8Array): boolean {
  const pubBytes = hexToBytes(publicKeyHex);
  try {
    return p256.verify(signature, digest, pubBytes, { lowS: false });
  } catch {
    try {
      return secp256k1.verify(signature, digest, pubBytes, { lowS: false });
    } catch {
      return false;
    }
  }
}

function verifyEcdsaProofLegacy(m: JSONMap): boolean {
  const proofMap = getFirstProof(m);
  if (!proofMap || typeof proofMap !== 'object') {
    throw new Error('proof is missing or has unexpected format');
  }
  const proof = proofMap as JSONMap;
  const proofValue = proof.proofValue;
  if (typeof proofValue !== 'string' || !proofValue) {
    throw new Error('proof value is missing or invalid in the request');
  }
  const publicKeyHex = proof.verificationMethod;
  if (typeof publicKeyHex !== 'string' || !publicKeyHex) {
    throw new Error('proof verificationMethod is missing or invalid in the request');
  }

  const signatureBytes = hexToBytes(proofValue);

  const reqCopy: JSONMap = {};
  for (const [k, v] of Object.entries(m)) {
    if (k !== PROOF_FIELD) reqCopy[k] = v;
  }
  const message = new Uint8Array(Buffer.from(JSON.stringify(reqCopy), 'utf8'));
  const pubBytes = keyToBytes(publicKeyHex);
  return verifyJSONSignature(pubBytes, message, signatureBytes);
}

function getFirstProof(m: JSONMap): unknown {
  const raw = m[PROOF_FIELD];
  if (Array.isArray(raw) && raw.length > 0) return raw[0];
  return raw;
}

export function parseRawToProof(proof: unknown): Proof {
  if (!proof) throw new Error('JSONMap has no proof');
  if (typeof proof !== 'object' || Array.isArray(proof)) {
    throw new Error('invalid proof format');
  }
  const p = proof as JSONMap;
  const result: Proof = {
    type: typeof p.type === 'string' ? p.type : '',
    created: typeof p.created === 'string' ? p.created : '',
    verificationMethod: typeof p.verificationMethod === 'string' ? p.verificationMethod : '',
    proofPurpose: typeof p.proofPurpose === 'string' ? p.proofPurpose : '',
  };
  if (typeof p.proofValue === 'string') result.proofValue = p.proofValue;
  if (typeof p.cryptosuite === 'string') result.cryptosuite = p.cryptosuite;
  if (typeof p.challenge === 'string') result.challenge = p.challenge;
  if (typeof p.domain === 'string') result.domain = p.domain;
  if (typeof p.jws === 'string') result.jws = p.jws;
  return result;
}

function signerDIDFromBody(m: JSONMap): string {
  const issuer = didFromField(m.issuer);
  if (issuer) return issuer;
  const holder = didFromField(m.holder);
  if (holder) return holder;
  throw new Error('body is missing required `issuer` (VC) or `holder` (VP) field');
}

function didFromField(v: unknown): string | null {
  if (typeof v === 'string') return v || null;
  if (v && typeof v === 'object' && !Array.isArray(v)) {
    const id = (v as JSONMap).id;
    if (typeof id === 'string' && id) return id;
  }
  return null;
}

function strictPurposeCheck(
  doc: DIDDocument,
  vm: VerificationMethodEntry,
  proofPurpose: string,
  proofCreated: string,
): void {
  if (isHardRevocationReason(vm.revocationReason)) {
    throw new Error(
      `verification method '${vm.id}' revoked with hard reason '${vm.revocationReason}'`,
    );
  }
  if (vm.revoked) {
    const created = new Date(proofCreated);
    if (isNaN(created.getTime())) {
      throw new Error(`invalid proof.created timestamp '${proofCreated}'`);
    }
    if (created.getTime() >= vm.revoked.getTime()) {
      throw new Error(
        `verification method '${vm.id}' was revoked at ${vm.revoked.toISOString()}; proof.created ${created.toISOString()} is not earlier`,
      );
    }
  }
  let arr: string[];
  if (proofPurpose === 'authentication') arr = doc.authentication;
  else if (proofPurpose === 'assertionMethod') arr = doc.assertionMethod;
  else throw new Error(`unsupported proofPurpose '${proofPurpose}'`);

  if (!idInArray(vm.id, doc.id, arr)) {
    throw new Error(
      `verification method '${vm.id}' is not granted purpose '${proofPurpose}' on DID '${doc.id}'`,
    );
  }
}

function idInArray(vmID: string, docID: string, arr: string[]): boolean {
  let frag = vmID;
  if (vmID.startsWith(docID + '#')) frag = vmID.slice(docID.length);
  return arr.some((ref) => ref === vmID || ref === frag);
}

function jwtVerificationMethodURL(m: JSONMap): string {
  const proof = m[PROOF_FIELD];
  if (proof && typeof proof === 'object' && !Array.isArray(proof)) {
    const p = proof as JSONMap;
    if (typeof p.verificationMethod === 'string' && p.verificationMethod) {
      return p.verificationMethod;
    }
    if (typeof p.jws === 'string' && p.jws) {
      const kid = jwsKid(p.jws);
      if (kid) return kid;
    }
  }
  throw new Error('token is missing verification method id (kid/verificationMethod)');
}

function jwsKid(jws: string): string | null {
  const dot = jws.indexOf('.');
  if (dot <= 0) return null;
  try {
    const headerBytes = Buffer.from(jws.slice(0, dot), 'base64url');
    const hdr = JSON.parse(headerBytes.toString('utf8')) as JSONMap;
    if (typeof hdr.kid === 'string' && hdr.kid) return hdr.kid;
  } catch {
    return null;
  }
  return null;
}
