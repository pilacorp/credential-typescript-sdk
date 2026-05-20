/**
 * Top-level VP parser — Node port of vp/presentation.go.
 */
import { isJSONPresentationBytes, isJWTPresentation } from './presentation-helper';
import { JSONPresentation } from './json-presentation';
import { JWTPresentation } from './jwt-presentation';
import type { Presentation, PresentationContents, PresentationOptions } from './types';

export { init } from './config';
export * from './types';
export { JWTPresentation } from './jwt-presentation';
export { JSONPresentation } from './json-presentation';

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
  if (isJWTPresentation(asString)) {
    return JWTPresentation.parse(asString, opts);
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
