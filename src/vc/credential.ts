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
  TypeEnvelopedVC,
  TypeVCJWT,
  TypeVCSDJWT,
} from './jose-credential';
import type { Credential, CredentialContents, CredentialOptions } from './types';

export { init } from './config';
export * from './types';
export { JWTCredential } from './jwt-credential';
export { JSONCredential } from './json-credential';
export { JOSECredential, TypeVCJWT, TypeVCSDJWT, TypeEnvelopedVC, isJOSECredentialTyp } from './jose-credential';
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
    // EnvelopedVerifiableCredential unwrap (W3C VC 2.0 / vc-jose-cose §4.13).
    // The data: URI and the type are both load-bearing: unwrapping on the id
    // alone would let any JSON borrow an id and be read as whatever it points
    // at, discarding its own type/issuer/subject. Port of ParseCredential.
    const enveloped = unwrapEnvelopedCredential(asString);
    if (enveloped) return JOSECredential.parse(enveloped, opts);
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

/**
 * If the JSON object is an EnvelopedVerifiableCredential carrying a
 * `data:application/vc+jwt,` or `data:application/vc+sd-jwt,` id, returns the
 * enveloped token. Throws if the id has the prefix but the type is not
 * EnvelopedVerifiableCredential. Returns null for a plain JSON credential.
 */
function unwrapEnvelopedCredential(s: string): string | null {
  let peek: unknown;
  try {
    peek = JSON.parse(s);
  } catch {
    return null;
  }
  if (!peek || typeof peek !== 'object' || Array.isArray(peek)) return null;
  const obj = peek as Record<string, unknown>;
  const id = obj.id;
  if (typeof id !== 'string') return null;
  for (const mediaType of [TypeVCJWT, TypeVCSDJWT]) {
    const prefix = `data:application/${mediaType},`;
    if (!id.startsWith(prefix)) continue;
    const types = Array.isArray(obj.type) ? obj.type : obj.type ? [obj.type] : [];
    if (!types.includes(TypeEnvelopedVC)) {
      throw new Error(
        `credential carries a ${prefix} id but its type is not ${TypeEnvelopedVC}`,
      );
    }
    return id.slice(prefix.length);
  }
  return null;
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
