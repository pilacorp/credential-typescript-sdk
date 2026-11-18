/**
 * DID document & verification method types — Node port of
 * credential/common/verification-method/verification_method.go
 */

import { parseRFC3339Nanos } from '../util/time';

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

// Go's time.Parse also takes ',' as the fraction separator.
const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:[.,](\d+))?(Z|[+-]\d{2}:\d{2})$/;

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

/**
 * `revoked` in nanoseconds since the epoch. Uses the original RFC3339Nano text
 * (full precision, like Go's time.Time) while it still denotes the same instant
 * as the `revoked` Date; otherwise falls back to the Date at ms precision.
 */
export function revokedNanos(vm: VerificationMethodEntry): bigint {
  const ms = BigInt(vm.revoked!.getTime());
  if (vm.revokedText) {
    try {
      const n = parseRFC3339Nanos(vm.revokedText);
      if (n / 1_000_000n === ms || (n < 0n && (n - 999_999n) / 1_000_000n === ms)) return n;
    } catch {
      /* stale text: fall through */
    }
  }
  return ms * 1_000_000n;
}

// Go decodes the document into typed fields with encoding/json: null leaves a
// field unset, any other value of the wrong JSON type fails the whole document.
function typed<T>(v: unknown, field: string, ok: (x: unknown) => boolean, unset: T): T {
  if (v === undefined || v === null) return unset;
  if (!ok(v)) throw new Error(`invalid DID document: field "${field}" has the wrong type`);
  return v as T;
}
const isString = (x: unknown) => typeof x === 'string';
const isObject = (x: unknown) => typeof x === 'object' && x !== null && !Array.isArray(x);
const isStringArray = (x: unknown) => Array.isArray(x) && x.every(isString);
const str = (v: unknown, field: string) => typed(v, field, isString, '');

/** Parse a raw resolver response into a typed DIDDocument. */
export function parseDIDDocument(raw: Record<string, unknown>): DIDDocument {
  const vms = typed<unknown[]>(raw.verificationMethod, 'verificationMethod', Array.isArray, []);
  const verificationMethod: VerificationMethodEntry[] = vms.map((entry) => {
    const e = typed<Record<string, unknown>>(entry, 'verificationMethod[]', isObject, {});
    const out: VerificationMethodEntry = {
      id: str(e.id, 'id'),
      type: str(e.type, 'type'),
      controller: str(e.controller, 'controller'),
    };
    const hex = str(e.publicKeyHex, 'publicKeyHex');
    if (hex) out.publicKeyHex = hex;
    const jwk = typed<Record<string, unknown> | undefined>(e.publicKeyJwk, 'publicKeyJwk', isObject, undefined);
    if (jwk) {
      for (const k of ['kty', 'crv', 'x', 'y', 'n', 'e']) str(jwk[k], `publicKeyJwk.${k}`);
      out.publicKeyJwk = jwk as unknown as JWK;
    }
    const mb = str(e.publicKeyMultibase, 'publicKeyMultibase');
    if (mb) out.publicKeyMultibase = mb;
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
    const reason = str(e.revocationReason, 'revocationReason');
    if (reason) out.revocationReason = reason;
    return out;
  });

  return {
    '@context': typed(raw['@context'], '@context', isStringArray, [] as string[]),
    id: str(raw.id, 'id'),
    verificationMethod,
    authentication: typed(raw.authentication, 'authentication', isStringArray, [] as string[]),
    assertionMethod: typed(raw.assertionMethod, 'assertionMethod', isStringArray, [] as string[]),
    controller: raw.controller as string | string[] | undefined,
    didDocumentMetadata: typed<Record<string, unknown> | undefined>(
      raw.didDocumentMetadata, 'didDocumentMetadata', isObject, undefined),
  };
}
