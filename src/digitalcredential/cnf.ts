import { hasOwn } from '../common/util/json';
import { p256FromJWK } from './jws-compact';

/**
 * Why a cnf claim gives no Holder key. unsupported: the cnf may be valid, but
 * this SDK binds only to cnf.jwk holding an EC P-256 or secp256k1 key.
 * Otherwise the cnf is malformed.
 */
export class CnfError extends Error {
  readonly cause?: unknown;

  constructor(
    message: string,
    readonly unsupported: boolean,
    cause?: unknown,
  ) {
    super(message);
    this.name = 'CnfError';
    if (cause !== undefined) this.cause = cause;
  }
}

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

/** Reads the Holder's public key from the value of a cnf claim (RFC 7800 §3). The one reader of cnf.jwk for issue and verify. */
export function cnfKey(cnf: unknown): Uint8Array {
  if (!isObject(cnf)) throw new CnfError('cnf is not a JSON object', false);
  // RFC 7800 §3.1: cnf represents a single proof-of-possession key.
  if (['jwk', 'jwe', 'jku'].filter((m) => hasOwn(cnf, m)).length > 1) {
    throw new CnfError('cnf has more than one of jwk, jwe and jku, and only one is allowed', false);
  }
  if (!hasOwn(cnf, 'jwk')) {
    throw new CnfError('cnf has no jwk member, and this SDK binds only to cnf.jwk holding an EC P-256 or secp256k1 key', true);
  }
  const jwk = cnf.jwk;
  if (!isObject(jwk)) throw new CnfError('cnf.jwk is not a JSON object', false);
  // RFC 7800 §3.2: a symmetric key goes in jwk only when the JWT is encrypted.
  if (jwk.kty === 'oct') throw new CnfError('cnf.jwk is a symmetric key in a JWT that is not encrypted', false);
  if (hasOwn(jwk, 'd')) throw new CnfError('cnf.jwk carries a private key (d)', false);
  if (typeof jwk.kty !== 'string') throw new CnfError('cnf.jwk kty is missing or not a string', false);
  if (jwk.kty !== 'EC') throw new CnfError(`cnf.jwk kty ${JSON.stringify(jwk.kty.slice(0, 16))} is not one this SDK binds`, true);
  if (typeof jwk.crv !== 'string') throw new CnfError('cnf.jwk crv is missing or not a string', false);
  if (jwk.crv !== 'P-256' && jwk.crv !== 'secp256k1') {
    throw new CnfError(`cnf.jwk crv ${JSON.stringify(jwk.crv.slice(0, 16))} is not one this SDK binds`, true);
  }
  if (jwk.crv === 'secp256k1') checkES256KMembers(jwk);
  try {
    return p256FromJWK(jwk as Parameters<typeof p256FromJWK>[0]);
  } catch (err) {
    throw new CnfError(`cnf.jwk is not a usable key: ${(err as Error).message}`, false, err);
  }
}

// RFC 8812 §3.2: what alg, use and key_ops of a secp256k1 JWK must say when present.
function checkES256KMembers(jwk: Record<string, unknown>): void {
  if (hasOwn(jwk, 'alg') && jwk.alg !== 'ES256K') throw new CnfError('cnf.jwk alg of a secp256k1 key must be ES256K', false);
  if (hasOwn(jwk, 'use') && jwk.use !== 'sig') throw new CnfError('cnf.jwk use of a secp256k1 key must be sig', false);
  if (hasOwn(jwk, 'key_ops') && !(Array.isArray(jwk.key_ops) && jwk.key_ops.includes('verify'))) {
    throw new CnfError('cnf.jwk key_ops of a secp256k1 key must be an array including verify', false);
  }
}
