/**
 * In-memory resolver and verification-method builders — Node port of
 * credential/common/verification-method/static_resolver.go
 */
import { KeyObject } from 'node:crypto';
import { p256 } from '@noble/curves/nist';
import type { ResolverProvider } from './provider';
import type { DIDDocument, VerificationMethodEntry } from './verification-method';
import { encodeP256PublicMultibase } from './multikey';

/**
 * A ResolverProvider backed by a fixed set of DID documents. It does no I/O,
 * so it suits tests and offline use, e.g. verifying credentials signed with
 * key types the production DID resolver does not publish (RSA, P-256).
 */
export class StaticResolver implements ResolverProvider {
  private readonly docs = new Map<string, DIDDocument>();

  constructor(...docs: DIDDocument[]) {
    for (const d of docs) this.add(d);
  }

  /** Registers (or replaces) a document, keyed by its id. */
  add(doc: DIDDocument | null | undefined): void {
    if (doc?.id) this.docs.set(doc.id, doc);
  }

  async resolveDocument(did: string): Promise<DIDDocument> {
    const doc = this.docs.get(did);
    if (!doc) throw new Error(`static resolver: unknown did ${JSON.stringify(did)}`);
    return doc;
  }
}

export function newStaticResolver(...docs: DIDDocument[]): StaticResolver {
  return new StaticResolver(...docs);
}

/** A DID document exposing `vms`, listing every VM under assertionMethod and authentication. */
export function newDIDDocument(did: string, ...vms: VerificationMethodEntry[]): DIDDocument {
  return {
    '@context': [],
    id: did,
    verificationMethod: vms,
    assertionMethod: vms.map((v) => v.id),
    authentication: vms.map((v) => v.id),
  };
}

/** EcdsaSecp256k1VerificationKey2019 VM (used by ecdsa-rdfc-2019). `fragment` has no leading "#". */
export function newSecp256k1VM(did: string, fragment: string, pubKeyHex: string): VerificationMethodEntry {
  return {
    id: `${did}#${fragment}`,
    type: 'EcdsaSecp256k1VerificationKey2019',
    controller: did,
    publicKeyHex: pubKeyHex,
  };
}

/** JsonWebKey2020 VM from an RSA public key (a KeyObject or base64url n/e). Used by JsonWebSignature2020. */
export function newRSAVM(
  did: string,
  fragment: string,
  pub: KeyObject | { n: string; e: string },
): VerificationMethodEntry {
  const jwk = pub instanceof KeyObject ? pub.export({ format: 'jwk' }) : pub;
  return {
    id: `${did}#${fragment}`,
    type: 'JsonWebKey2020',
    controller: did,
    publicKeyJwk: { kty: 'RSA', n: jwk.n as string, e: jwk.e as string },
  };
}

function p256Uncompressed(pub: Uint8Array, who: string): Uint8Array {
  if (!pub) throw new Error(`${who} requires a non-nil public key`);
  try {
    return p256.ProjectivePoint.fromHex(pub).toRawBytes(false);
  } catch {
    throw new Error(`${who} requires a P-256 key`);
  }
}

/** JsonWebKey2020 VM from a P-256 public key (SEC1 compressed or uncompressed). */
export function newP256VM(did: string, fragment: string, pub: Uint8Array): VerificationMethodEntry {
  const raw = p256Uncompressed(pub, 'NewP256VM');
  return {
    id: `${did}#${fragment}`,
    type: 'JsonWebKey2020',
    controller: did,
    publicKeyJwk: {
      kty: 'EC',
      crv: 'P-256',
      x: Buffer.from(raw.slice(1, 33)).toString('base64url'),
      y: Buffer.from(raw.slice(33, 65)).toString('base64url'),
    },
  };
}

/**
 * Multikey VM from a P-256 public key: the representation the W3C ecdsa-rdfc-2019
 * and ecdsa-sd-2023 suites specify (newP256VM publishes the same key as a JWK).
 */
export function newP256MultikeyVM(did: string, fragment: string, pub: Uint8Array): VerificationMethodEntry {
  const raw = p256Uncompressed(pub, 'NewP256MultikeyVM');
  return {
    id: `${did}#${fragment}`,
    type: 'Multikey',
    controller: did,
    publicKeyMultibase: encodeP256PublicMultibase(raw),
  };
}
