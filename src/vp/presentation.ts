/**
 * Top-level VP parser — Node port of vp/presentation.go.
 */
import { isJSONPresentationBytes, isJWTPresentation, isSDJWTShaped } from './presentation-helper';
import { JSONPresentation } from './json-presentation';
import { JWTPresentation } from './jwt-presentation';
import { JOSEPresentation, isJOSEPresentationTyp } from './jose-presentation';
import type { Presentation, PresentationContents, PresentationOptions } from './types';

export { init } from './config';
export * from './types';
export { JWTPresentation } from './jwt-presentation';
export { JSONPresentation } from './json-presentation';
export { JOSEPresentation, TypeVPJWT, TypeJOSE } from './jose-presentation';

export async function parsePresentation(
  rawPresentation: Uint8Array | string,
  opts: PresentationOptions = {},
): Promise<Presentation> {
  if (
    rawPresentation === undefined ||
    rawPresentation === null ||
    (typeof rawPresentation !== 'string' && rawPresentation.length === 0) ||
    (typeof rawPresentation === 'string' && rawPresentation.length === 0)
  ) {
    throw new Error('presentation is empty');
  }
  const asString = typeof rawPresentation === 'string'
    ? rawPresentation
    : Buffer.from(rawPresentation).toString('utf8');

  if (isJSONPresentationBytes(asString)) {
    return JSONPresentation.parse(asString, opts);
  }
  const valStr = asString.trim().replace(/^"|"$/g, '');
  if (isJWTPresentation(valStr)) {
    // vp+jwt (vc-jose-cose) must verify through the JWT verifier (holder
    // binding); route by the header typ, defaulting to the VC 1.1 JWT path.
    if (isJOSEPresentationTyp(peekPresentationTyp(valStr))) {
      return JOSEPresentation.parse(valStr, opts);
    }
    return JWTPresentation.parse(valStr, opts);
  }
  if (isSDJWTShaped(valStr)) {
    throw new Error('presentation carries SD-JWT disclosures, which are not supported for presentations');
  }
  throw new Error('failed to parse presentation');
}

export async function parsePresentationWithValidation(
  rawPresentation: Uint8Array | string,
): Promise<Presentation> {
  return parsePresentation(rawPresentation, {
    validateVC: true,
    verifyProof: true,
  });
}

/** Free-function parsers per type (go ParseJSONPresentation / ParseJWTPresentation / ParseJOSEPresentation). */
export function parseJSONPresentation(raw: Uint8Array | string, opts: PresentationOptions = {}): Promise<JSONPresentation> {
  return JSONPresentation.parse(raw, opts);
}

export function parseJWTPresentation(raw: string, opts: PresentationOptions = {}): Promise<JWTPresentation> {
  return JWTPresentation.parse(raw, opts);
}

export function parseJOSEPresentation(raw: string, opts: PresentationOptions = {}): Promise<JOSEPresentation> {
  return JOSEPresentation.parse(raw, opts);
}

export async function newJWTPresentation(
  vpc: PresentationContents,
  opts: PresentationOptions = {},
): Promise<JWTPresentation> {
  return JWTPresentation.create(vpc, opts);
}

export async function newJSONPresentation(
  vpc: PresentationContents,
  opts: PresentationOptions = {},
): Promise<JSONPresentation> {
  return JSONPresentation.create(vpc, opts);
}

export async function newJOSEPresentation(
  vpc: PresentationContents,
  opts: PresentationOptions = {},
): Promise<JOSEPresentation> {
  return JOSEPresentation.create(vpc, opts);
}

/** Decode the JWS header's `typ` claim, or undefined if unreadable. */
function peekPresentationTyp(valStr: string): string | undefined {
  const parts = valStr.split('.');
  if (parts.length < 2) return undefined;
  try {
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    return typeof header.typ === 'string' ? header.typ : undefined;
  } catch {
    return undefined;
  }
}
