/**
 * JWT signing key binding — port of credential/common/jwt/signing_key.go.
 *
 * A SigningKey is the verification method a JWT is issued under: the kid and
 * alg the header carries, and the public key a fresh signature must verify
 * against. A parsed token has no key (null) and only gets the shape check.
 */
import { p256 } from '@noble/curves/nist';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { hexToBytes } from '../crypto/hex';
import {
  KeyKind,
  publicKeyHexFromVM,
  ResolverProvider,
  resolveSigningVM,
  vmKeyKind,
} from '../verification-method';
import { decodeSecp256k1PublicKey } from './verifier';

export interface SigningKey {
  id: string;
  alg: string;
  kind: KeyKind;
  publicKeyHex: string;
}

/** JOSE alg for a key kind (go AlgForKeyKind); RSA has no JWT alg here. */
export function jwtAlgForKeyKind(kind: KeyKind | null): string {
  if (kind === 'secp256k1') return 'ES256K';
  if (kind === 'P-256') return 'ES256';
  throw new Error(`key kind ${String(kind)} cannot sign a JWT: only secp256k1 (ES256K) and P-256 (ES256)`);
}

export async function resolveSigningKey(
  did: string,
  purpose: string,
  pinnedKid: string,
  resolver: ResolverProvider | null,
): Promise<SigningKey> {
  const { vm, url } = await resolveSigningVM(did, purpose, pinnedKid, resolver);
  const kind = vmKeyKind(vm);
  if (!kind) throw new Error(`verification method '${url}' has an unrecognized key type`);
  let alg: string;
  try {
    alg = jwtAlgForKeyKind(kind);
  } catch (err) {
    throw new Error(`verification method '${url}': ${(err as Error).message}`);
  }
  return { id: url, alg, kind, publicKeyHex: publicKeyHexFromVM(vm) };
}

/** go jwtutil.TrimRecoveryByte: 65-byte r||s||v becomes r||s. */
export function trimRecoveryByte(sig: Uint8Array): Uint8Array {
  return sig.length === 65 ? sig.subarray(0, 64) : sig;
}

/**
 * Checks a raw signature over signingInput against the key and returns it
 * base64url-encoded (go SigningKey.Accept). A null key skips the key check but
 * not the 64-byte shape check.
 */
export function acceptSignature(
  key: SigningKey | null,
  signingInput: string,
  signature: Uint8Array,
): string {
  const sig = trimRecoveryByte(signature);
  if (sig.length !== 64) {
    throw new Error(
      `signature must be 64-byte r||s (65 with a trailing recovery id is trimmed), got ${sig.length} bytes: the signer returned another format, not a JWS signature`,
    );
  }
  if (key) {
    const hash = sha256(Buffer.from(signingInput, 'utf8'));
    const pub = hexToBytes(key.publicKeyHex.replace(/^0x/i, ''));
    let ok = false;
    try {
      ok =
        key.kind === 'P-256'
          ? p256.verify(sig, hash, pub, { lowS: false })
          : secp256k1.verify(sig, hash, decodeSecp256k1PublicKey(key.publicKeyHex), { lowS: false });
    } catch {
      ok = false;
    }
    if (!ok) {
      throw new Error(
        `the signature does not verify against verification method '${key.id}': it was made by another key or over data other than the signing input — to sign with another key, pass verificationMethodKey when building the token`,
      );
    }
  }
  return Buffer.from(sig).toString('base64url');
}
