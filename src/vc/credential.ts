/**
 * Top-level VC parser — Node port of vc/credential.go.
 *
 * Dispatches by content shape:
 *  - JSON object → JSONCredential
 *  - SD-JWT / JWT (header.payload.signature) → JWTCredential
 */
import { isSDJWT } from '../common/sdjwt';
import { isJWTCredentialString, JWTCredential } from './jwt-credential';
import { JSONCredential } from './json-credential';
import {
  isJOSECredentialTyp,
  JOSECredential,
  peekJwtTyp,
} from './jose-credential';
import type { Credential, CredentialContents, CredentialOptions } from './types';

export { init } from './config';
export * from './types';
export { JWTCredential } from './jwt-credential';
export { JSONCredential } from './json-credential';
export { JOSECredential, TypeVCJWT, TypeVCSDJWT, isJOSECredentialTyp } from './jose-credential';
export { ECDSASDCredential, dotPathsToPointers } from './ecdsasd-credential';

export async function parseCredential(
  rawCredential: Uint8Array | string,
  opts: CredentialOptions = {},
): Promise<Credential> {
  if (!rawCredential || (typeof rawCredential !== 'string' && rawCredential.length === 0)) {
    throw new Error('JSON string is empty');
  }

  const asString = typeof rawCredential === 'string'
    ? rawCredential
    : Buffer.from(rawCredential).toString('utf8');

  if (isJSONCredential(asString)) {
    return JSONCredential.parse(asString, opts);
  }

  if (isSDJWT(asString) || isJWTCredentialString(asString)) {
    const typ = peekJwtTyp(asString);
    if (typ && typ.endsWith('+sd-jwt') && !isJOSECredentialTyp(typ)) {
      throw new Error(
        `failed to parse credential: unsupported SD-JWT typ "${typ}": only vc+sd-jwt is read`,
      );
    }
    if (isJOSECredentialTyp(typ)) {
      return JOSECredential.parse(asString, opts);
    }
    return JWTCredential.parse(asString, opts);
  }

  throw new Error('failed to parse credential: not a valid JSON, SD-JWT, or JWT credential');
}

export async function parseCredentialWithValidation(
  rawCredential: Uint8Array | string,
): Promise<Credential> {
  return parseCredential(rawCredential, {
    validateSchema: true,
    verifyProof: true,
  });
}

export async function newJWTCredential(
  vcc: import('./types').CredentialContents,
  opts: CredentialOptions = {},
): Promise<JWTCredential> {
  return JWTCredential.create(vcc, opts);
}

export async function newJSONCredential(
  vcc: CredentialContents,
  opts: CredentialOptions = {},
): Promise<JSONCredential> {
  return JSONCredential.create(vcc, opts);
}

export async function newJOSECredential(
  vcc: CredentialContents,
  opts: CredentialOptions = {},
): Promise<JOSECredential> {
  return JOSECredential.create(vcc, opts);
}

function isJSONCredential(s: string): boolean {
  const trimmed = s.trim();
  if (!trimmed) return false;
  try {
    const parsed = JSON.parse(trimmed);
    return !!parsed && typeof parsed === 'object' && !Array.isArray(parsed);
  } catch {
    return false;
  }
}
