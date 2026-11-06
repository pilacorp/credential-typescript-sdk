/**
 * JWT verifier — Node port of credential/common/jwt/verifier.go
 *
 * Decodes the kid + iss from the JWT, resolves the DID Document via the
 * supplied ResolverProvider, picks the VM by id, then runs:
 *   1. ES256K crypto verification
 *   2. Strict-purpose check (vc → assertionMethod, vp → authentication)
 *   3. Revocation check (hard reason short-circuits; soft reason compares iat)
 */
import { p256 } from '@noble/curves/nist';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { hexToBytes } from '../crypto/hex';
import {
  DIDDocument,
  findVerificationMethod,
  isHardRevocationReason,
  publicKeyHexFromVM,
  ResolverProvider,
  VerificationMethodEntry,
} from '../verification-method';

export class JWTVerifier {
  constructor(private readonly docResolver: ResolverProvider | null) {}

  async verifyJWT(tokenString: string): Promise<void> {
    const parts = tokenString.split('.');
    if (parts.length !== 3) throw new Error('invalid JWT format');

    const headerJSON = Buffer.from(parts[0], 'base64url').toString('utf8');
    let header: Record<string, unknown>;
    try {
      header = JSON.parse(headerJSON);
    } catch (err) {
      throw new Error(`invalid header: ${(err as Error).message}`);
    }

    const alg = header.alg;
    if (alg !== 'ES256K' && alg !== 'ES256') {
      throw new Error(`unsupported algorithm: ${alg}`);
    }

    const kid = header.kid;
    if (typeof kid !== 'string') throw new Error('kid not found in header');

    if (!this.docResolver) throw new Error('document resolver is not configured');

    // Which property names the signer depends on the kind: a credential is
    // signed by its issuer, a presentation by its holder. The purpose is read
    // before the signer, and both come from the payload — never from the
    // attacker-chosen kid. Port of credential/common/jwt/verifier.go.
    const body = decodePayload(parts[1]);
    const purpose = jwtProofPurpose(header, body);
    const signer = jwtSigner(body, purpose);

    const doc = await this.docResolver.resolveDocument(signer);
    const vm = findVerificationMethod(doc, kid);

    // The header must not claim an algorithm the VM key cannot produce.
    const wantAlg = algForVM(vm);
    if (alg !== wantAlg) {
      throw new Error(
        `JWT alg "${alg}" does not match verification method '${vm.id}', which holds a ${wantAlg === 'ES256' ? 'P-256' : 'secp256k1'} key`,
      );
    }
    const publicKeyHex = publicKeyHexFromVM(vm);

    const signingString = parts[0] + '.' + parts[1];
    const signature = new Uint8Array(Buffer.from(parts[2], 'base64url'));
    // RFC 7518 §3.4 / RFC 8812 §3.2: a JWS ECDSA signature is exactly 64 bytes.
    if (signature.length !== 64) {
      throw new Error(`invalid signature length: got ${signature.length}, want 64`);
    }
    const rs = signature;
    const hash = sha256(Buffer.from(signingString, 'utf8'));
    const ok =
      alg === 'ES256'
        ? p256.verify(rs, hash, hexToBytes(publicKeyHex.replace(/^0x/i, '')), { lowS: false })
        : secp256k1.verify(rs, hash, decodeSecp256k1PublicKey(publicKeyHex), { lowS: false });
    if (!ok) {
      throw new Error('signature verification failed');
    }

    const issuedAt = jwtIssuedAt(parts[1]);
    strictPurposeCheck(doc, vm, purpose, issuedAt);
  }
}

/** JOSE algorithm the verification method's key can produce (go AlgForKeyKind). */
function algForVM(vm: VerificationMethodEntry): string {
  if (vm.publicKeyJwk) {
    if (vm.publicKeyJwk.crv === 'P-256') return 'ES256';
    if (vm.publicKeyJwk.crv === 'secp256k1') return 'ES256K';
    throw new Error(`verification method '${vm.id}' has unsupported JWK curve ${vm.publicKeyJwk.crv}`);
  }
  if (vm.publicKeyMultibase) return 'ES256'; // P-256 Multikey
  if (vm.publicKeyHex) return 'ES256K'; // secp256k1 only (see publicKeyHexFromVM)
  if (vm.type === 'EcdsaSecp256k1VerificationKey2019') return 'ES256K';
  throw new Error(`verification method '${vm.id}' has an unrecognized key type for JWT`);
}

export function newJWTVerifier(resolver: ResolverProvider): JWTVerifier {
  return new JWTVerifier(resolver);
}

export function decodeSecp256k1PublicKey(publicKeyHex: string): Uint8Array {
  const clean = publicKeyHex.startsWith('0x') || publicKeyHex.startsWith('0X')
    ? publicKeyHex.slice(2)
    : publicKeyHex;
  const bytes = hexToBytes(clean);
  if (bytes.length === 33 && (bytes[0] === 0x02 || bytes[0] === 0x03)) {
    return secp256k1.ProjectivePoint.fromHex(bytes).toRawBytes(false);
  }
  if (bytes.length === 65 && bytes[0] === 0x04) {
    return bytes;
  }
  if (bytes.length === 64) {
    const out = new Uint8Array(65);
    out[0] = 0x04;
    out.set(bytes, 1);
    return out;
  }
  throw new Error('unsupported public key format');
}

/**
 * Returns the DID whose key signed the JWT, refusing a token whose `iss`
 * disagrees with the property that names the signer. A credential is signed by
 * its issuer, a presentation by its holder — so the two are never crossed.
 * Port of credential/common/jwt/verifier.go jwtSigner.
 */
function jwtSigner(body: Record<string, unknown>, purpose: string): string {
  const field = purpose === 'assertionMethod' ? 'issuer' : 'holder';

  // VC 1.1 nests the document under a vc/vp claim; read the property there when
  // present so a nested issuer cannot disagree with iss unnoticed.
  let doc = body;
  if (isPlainObject(body.vc)) doc = body.vc as Record<string, unknown>;
  else if (isPlainObject(body.vp)) doc = body.vp as Record<string, unknown>;

  // A key that differs from `field` only by case would be read by a
  // case-insensitive consumer but not here, letting a signer name the victim
  // under a key this lookup never sees.
  for (const k of Object.keys(doc)) {
    if (k !== field && foldCase(k) === foldCase(field)) {
      throw new Error(`JWT carries "${k}", which differs from ${field} only by case`);
    }
  }

  const present = Object.prototype.hasOwnProperty.call(doc, field);
  const claimed = didFromClaim(doc[field]);
  if (present && !claimed) {
    throw new Error(`JWT ${field} must be a string or an object with a string id`);
  }

  const iss = typeof body.iss === 'string' ? body.iss : '';
  if (iss && claimed && iss !== claimed) {
    throw new Error(`JWT iss "${iss}" does not match ${field} "${claimed}"`);
  }
  if (iss) return iss;
  if (claimed) return claimed;
  throw new Error(`JWT names no signer: both iss and ${field} are absent`);
}

function didFromClaim(v: unknown): string {
  if (typeof v === 'string') return v;
  if (isPlainObject(v)) {
    const id = (v as Record<string, unknown>).id;
    if (typeof id === 'string') return id;
  }
  return '';
}

function isPlainObject(v: unknown): boolean {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * Resolves the proofPurpose from the header typ and the payload, refusing a typ
 * that contradicts the payload or a payload whose kind is ambiguous.
 * Port of credential/common/jwt/verifier.go jwtProofPurpose.
 */
function jwtProofPurpose(header: Record<string, unknown>, body: Record<string, unknown>): string {
  const carried = purposeFromBody(body);
  const declared = purposeFromTyp(header);
  if (carried && declared && carried !== declared) {
    throw new Error(
      `JWT typ ${String(header.typ)} implies proofPurpose ${declared} but its payload is a ${documentKind(carried)}`,
    );
  }
  if (carried) return carried;
  if (declared) return declared;
  throw new Error('JWT has neither vc/vp claims nor vc+jwt/vp+jwt typ; cannot determine proofPurpose');
}

function purposeFromTyp(header: Record<string, unknown>): string {
  switch (header.typ) {
    case 'vc+jwt':
    case 'application/vc+jwt':
    case 'vc+sd-jwt':
    case 'application/vc+sd-jwt':
      return 'assertionMethod';
    case 'vp+jwt':
    case 'application/vp+jwt':
      return 'authentication';
    default:
      return '';
  }
}

function purposeFromBody(body: Record<string, unknown>): string {
  const hasVC = body.vc !== undefined;
  const hasVP = body.vp !== undefined;
  if (hasVC && hasVP) throw new Error('JWT carries both vc and vp claims; its kind is ambiguous');
  if (hasVC) return 'assertionMethod';
  if (hasVP) return 'authentication';
  const type = body.type;
  if (Array.isArray(type)) {
    let found = '';
    for (const v of type) {
      const p = purposeFromType(typeof v === 'string' ? v : '');
      if (!p) continue;
      if (found && found !== p) {
        throw new Error('JWT type names both a credential and a presentation; its kind is ambiguous');
      }
      found = p;
    }
    return found;
  }
  if (typeof type === 'string') return purposeFromType(type);
  return '';
}

function purposeFromType(t: string): string {
  if (t === 'VerifiableCredential') return 'assertionMethod';
  if (t === 'VerifiablePresentation') return 'authentication';
  return '';
}

function documentKind(purpose: string): string {
  return purpose === 'assertionMethod' ? 'credential' : 'presentation';
}

function jwtIssuedAt(payloadB64: string): Date | null {
  const body = decodePayload(payloadB64);
  const raw = body.iat;
  if (raw === undefined || raw === null) return null;
  let sec: number;
  if (typeof raw === 'number') sec = Math.floor(raw);
  else if (typeof raw === 'string') sec = parseInt(raw, 10);
  else throw new Error(`invalid iat type: ${typeof raw}`);
  if (!Number.isFinite(sec) || sec <= 0) {
    throw new Error(`invalid iat value: ${raw}`);
  }
  return new Date(sec * 1000);
}

/** Unicode simple case folding like Go's strings.EqualFold ("ſ" folds to "s"). */
function foldCase(s: string): string {
  return Array.from(s, (c) => {
    const u = c.toUpperCase();
    return Array.from(u).length === 1 ? u.toLowerCase() : c.toLowerCase();
  }).join('');
}

function decodePayload(b64: string): Record<string, unknown> {
  try {
    const json = Buffer.from(b64, 'base64url').toString('utf8');
    const obj = JSON.parse(json);
    if (!obj || typeof obj !== 'object') throw new Error('payload is not an object');
    return obj as Record<string, unknown>;
  } catch (err) {
    throw new Error(`invalid payload JSON: ${(err as Error).message}`);
  }
}

function strictPurposeCheck(
  doc: DIDDocument,
  vm: VerificationMethodEntry,
  proofPurpose: string,
  issuedAt: Date | null,
): void {
  if (isHardRevocationReason(vm.revocationReason)) {
    throw new Error(
      `verification method '${vm.id}' revoked with hard reason '${vm.revocationReason}'`,
    );
  }
  if (vm.revoked) {
    if (!issuedAt) {
      throw new Error(
        `verification method '${vm.id}' was revoked at ${vm.revoked.toISOString()} (missing iat for time-based revocation check)`,
      );
    }
    if (issuedAt.getTime() >= vm.revoked.getTime()) {
      throw new Error(
        `verification method '${vm.id}' was revoked at ${vm.revoked.toISOString()}; iat ${issuedAt.toISOString()} is not earlier`,
      );
    }
  }
  let arr: string[];
  if (proofPurpose === 'authentication') arr = doc.authentication;
  else if (proofPurpose === 'assertionMethod') arr = doc.assertionMethod;
  else throw new Error(`unsupported proofPurpose '${proofPurpose}'`);

  let frag = vm.id;
  if (vm.id.startsWith(doc.id + '#')) {
    frag = vm.id.slice(doc.id.length);
  }
  for (const ref of arr) {
    if (ref === vm.id || ref === frag) return;
  }
  throw new Error(
    `verification method '${vm.id}' is not granted purpose '${proofPurpose}' on DID '${doc.id}'`,
  );
}
