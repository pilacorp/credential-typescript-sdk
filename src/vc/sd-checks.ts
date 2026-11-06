/**
 * SD-JWT shape checks shared by the VC 1.1 JWT and vc+jwt paths — port of the
 * helpers in go vc/jose_credential.go and vc/jwt_credential.go.
 */
import type { JSONMap } from '../common/util/json';

const CREDENTIAL_SUBJECT = 'credentialSubject';

function isObj(v: unknown): v is JSONMap {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * Reports whether value holds anything the SD-JWT layer puts in a payload at any
 * depth: an `_sd` digest array, or the `{"...": digest}` array placeholder.
 */
export function carriesSDMachinery(value: unknown): boolean {
  if (isObj(value)) {
    if ('_sd' in value) return true;
    return Object.values(value).some(carriesSDMachinery);
  }
  if (Array.isArray(value)) {
    for (const child of value) {
      if (isObj(child) && Object.keys(child).length === 1 && '...' in child) return true;
      if (carriesSDMachinery(child)) return true;
    }
  }
  return false;
}

/** A VC 1.1 document or JWT payload carrying `_sd_alg`, `_sd` or `{"...":d}` anywhere. */
export function carriesSDJWT(m: JSONMap): boolean {
  if ('_sd_alg' in m) return true;
  if (isObj(m.vc) && '_sd_alg' in m.vc) return true;
  return carriesSDMachinery(m);
}

/**
 * Confines selective disclosure to the credentialSubject subtree. A vc+jwt
 * (subjectMayDisclose=false) must not carry the machinery anywhere.
 */
export function requireDisclosableAtTopLevel(m: JSONMap, subjectMayDisclose: boolean): void {
  if ('_sd' in m) {
    throw new Error(
      'the payload carries _sd at the root; selective disclosure belongs to claims inside credentialSubject, because nothing at the top level may be withheld',
    );
  }
  for (const [name, value] of Object.entries(m)) {
    if (name === CREDENTIAL_SUBJECT && subjectMayDisclose) continue;
    if (carriesSDMachinery(value)) {
      throw new Error(
        `selective disclosure is not permitted in "${name}"; only claims inside ${CREDENTIAL_SUBJECT} may be withheld`,
      );
    }
  }
}

const SECURED_CLAIMS = [
  '@context', 'type', 'issuer', 'validFrom', 'validUntil',
  'issuanceDate', 'expirationDate', 'credentialStatus',
];

/**
 * Refuses a token whose reconstruction introduced a claim a verifier decides
 * on, or whose signed payload hides top-level properties behind `_sd`.
 */
export function requireSecuredClaimsSigned(signed: JSONMap, reconstructed: JSONMap): void {
  for (const claim of SECURED_CLAIMS) {
    if (claim in signed) continue;
    if (claim in reconstructed) {
      throw new Error(
        `"${claim}" was selectively disclosed; a verifier decides on it, so it must be part of the signed payload`,
      );
    }
  }
  if ('_sd' in signed) {
    throw new Error(
      'the signed payload hides top-level properties behind _sd; selective disclosure is for claims inside credentialSubject',
    );
  }
}
