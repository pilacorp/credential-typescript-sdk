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

    const issuer = jwtIssuer(parts[1]);
    const doc = await this.docResolver.resolveDocument(issuer);
    const vm = findVerificationMethod(doc, kid);
    const publicKeyHex = publicKeyHexFromVM(vm);

    const signingString = parts[0] + '.' + parts[1];
    const signature = new Uint8Array(Buffer.from(parts[2], 'base64url'));
    if (signature.length !== 64 && signature.length !== 65) {
      throw new Error('invalid signature length');
    }
    const rs = signature.length === 65 ? signature.subarray(0, 64) : signature;
    const hash = sha256(Buffer.from(signingString, 'utf8'));
    const ok =
      alg === 'ES256'
        ? p256.verify(rs, hash, hexToBytes(publicKeyHex.replace(/^0x/i, '')), { lowS: false })
        : secp256k1.verify(rs, hash, decodeSecp256k1PublicKey(publicKeyHex), { lowS: false });
    if (!ok) {
      throw new Error('signature verification failed');
    }

    const purpose = jwtProofPurpose(parts[1]);
    const issuedAt = jwtIssuedAt(parts[1]);
    strictPurposeCheck(doc, vm, purpose, issuedAt);
  }
}

export function newJWTVerifier(resolver: ResolverProvider): JWTVerifier {
  return new JWTVerifier(resolver);
}

function decodeSecp256k1PublicKey(publicKeyHex: string): Uint8Array {
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

function jwtIssuer(payloadB64: string): string {
  const body = decodePayload(payloadB64);
  if (typeof body.iss === 'string' && body.iss) return body.iss;
  const issuer = body.issuer;
  if (typeof issuer === 'string' && issuer) return issuer;
  if (issuer && typeof issuer === 'object' && !Array.isArray(issuer)) {
    const id = (issuer as Record<string, unknown>).id;
    if (typeof id === 'string' && id) return id;
  }
  throw new Error('JWT body is missing required `iss` claim');
}

function jwtProofPurpose(payloadB64: string): string {
  const body = decodePayload(payloadB64);
  if (body.vc !== undefined) return 'assertionMethod';
  if (body.vp !== undefined) return 'authentication';
  const types = body.type;
  const names = Array.isArray(types) ? types : types ? [types] : [];
  if (names.includes('VerifiablePresentation')) return 'authentication';
  if (names.includes('VerifiableCredential')) return 'assertionMethod';
  throw new Error('JWT body has neither vc nor vp claim; cannot determine proofPurpose');
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
