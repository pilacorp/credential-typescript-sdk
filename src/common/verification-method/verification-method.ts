/**
 * DID document & verification method types — Node port of
 * credential/common/verification-method/verification_method.go
 */

export interface JWK {
  kty: string;
  crv: string;
  x: string;
  y: string;
}

export interface VerificationMethodEntry {
  id: string;
  type: string;
  controller: string;
  publicKeyHex?: string;
  publicKeyJwk?: JWK;
  publicKeyMultibase?: string;
  revoked?: Date;
  revocationReason?: string;
}

export interface DIDDocument {
  '@context': string[];
  id: string;
  verificationMethod: VerificationMethodEntry[];
  authentication: string[];
  assertionMethod: string[];
  controller?: string | string[];
  didDocumentMetadata?: Record<string, unknown>;
}

/** Parse a raw resolver response into a typed DIDDocument. */
export function parseDIDDocument(raw: Record<string, unknown>): DIDDocument {
  const vms = (raw.verificationMethod as unknown[]) ?? [];
  const verificationMethod: VerificationMethodEntry[] = vms.map((entry) => {
    const e = entry as Record<string, unknown>;
    const out: VerificationMethodEntry = {
      id: (e.id as string) ?? '',
      type: (e.type as string) ?? '',
      controller: (e.controller as string) ?? '',
    };
    if (typeof e.publicKeyHex === 'string') out.publicKeyHex = e.publicKeyHex;
    if (e.publicKeyJwk) out.publicKeyJwk = e.publicKeyJwk as JWK;
    if (typeof e.publicKeyMultibase === 'string') out.publicKeyMultibase = e.publicKeyMultibase;
    if (typeof e.revoked === 'string') {
      const d = new Date(e.revoked);
      if (!isNaN(d.getTime())) out.revoked = d;
    }
    if (typeof e.revocationReason === 'string') out.revocationReason = e.revocationReason;
    return out;
  });

  return {
    '@context': (raw['@context'] as string[]) ?? [],
    id: (raw.id as string) ?? '',
    verificationMethod,
    authentication: (raw.authentication as string[]) ?? [],
    assertionMethod: (raw.assertionMethod as string[]) ?? [],
    controller: raw.controller as string | string[] | undefined,
    didDocumentMetadata: raw.didDocumentMetadata as Record<string, unknown> | undefined,
  };
}
