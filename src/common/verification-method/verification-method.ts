/**
 * DID document & verification method types — Node port of
 * credential/common/verification-method/verification_method.go
 */

export interface JWK {
  kty: string;
  crv?: string;
  x?: string;
  y?: string;
  n?: string;
  e?: string;
  alg?: string;
}

export interface VerificationMethodEntry {
  id: string;
  type: string;
  controller: string;
  publicKeyHex?: string;
  publicKeyJwk?: JWK;
  publicKeyMultibase?: string;
  revoked?: Date;
  /**
   * `revoked` as Go's time.Time marshals it (RFC3339Nano, original offset, full
   * nanoseconds), kept so re-hashing a parsed document gives Go's DocHash. Only
   * used while it still denotes the same instant as `revoked`.
   */
  revokedText?: string;
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

const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$/;

/**
 * Strict RFC3339 parse like Go's time.Parse(time.RFC3339): returns the instant
 * (ms precision) and the text Go's MarshalJSON would emit for it (RFC3339Nano:
 * original offset, up to 9 fractional digits with trailing zeros trimmed).
 */
export function parseRFC3339Strict(value: string): { date: Date; text: string } {
  const m = RFC3339.exec(value);
  const bad = () => new Error(`invalid RFC3339 time: ${JSON.stringify(value)}`);
  if (!m) throw bad();
  const [y, mo, d, h, mi, s] = m.slice(1, 7).map(Number);
  const frac = (m[7] ?? '').slice(0, 9).replace(/0+$/, '');
  let offMin = 0;
  if (m[8] !== 'Z') {
    const oh = Number(m[8].slice(1, 3));
    const om = Number(m[8].slice(4, 6));
    if (oh > 23 || om > 59) throw bad();
    offMin = (m[8][0] === '-' ? -1 : 1) * (oh * 60 + om);
  }
  if (mo < 1 || mo > 12 || h > 23 || mi > 59 || s > 59) throw bad();
  const dt = new Date(0);
  dt.setUTCFullYear(y, mo - 1, d);
  if (dt.getUTCMonth() !== mo - 1 || dt.getUTCDate() !== d) throw bad();
  dt.setUTCHours(h, mi, s, Number((m[7] ?? '').slice(0, 3).padEnd(3, '0')));
  const date = new Date(dt.getTime() - offMin * 60_000);
  const off = offMin === 0 ? 'Z' : m[8];
  return { date, text: `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}${frac ? `.${frac}` : ''}${off}` };
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
    // Go unmarshals `revoked` as a strict RFC3339 *time.Time and fails the whole
    // document on a bad value or a non-string; ignoring it would treat a revoked
    // key as active.
    if (e.revoked !== undefined && e.revoked !== null) {
      if (typeof e.revoked !== 'string') {
        throw new Error(`verification method '${out.id}' has a non-string 'revoked' timestamp`);
      }
      try {
        const r = parseRFC3339Strict(e.revoked);
        out.revoked = r.date;
        out.revokedText = r.text;
      } catch {
        throw new Error(
          `verification method '${out.id}' has an unparseable 'revoked' timestamp: ${JSON.stringify(e.revoked)}`,
        );
      }
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
