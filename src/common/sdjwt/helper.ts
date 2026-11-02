/**
 * SD-JWT helpers — Node port of credential/common/sdjwt/helper.go
 *
 * Splits SD-JWT strings, decodes/hashes disclosures, and generates random salts.
 * Hash algorithms supported: sha-256, sha-384, sha-512.
 */
import { randomBytes } from 'crypto';
import { sha256 } from '@noble/hashes/sha256';
import { sha384, sha512 } from '@noble/hashes/sha512';
import { DecodedDisclosure, DisclosureInfo, ParsedSDJWT } from './types';

export const AlgSHA256 = 'sha-256';
export const AlgSHA384 = 'sha-384';
export const AlgSHA512 = 'sha-512';
export const DefaultHashAlgorithm = AlgSHA256;

export const supportedHashAlgorithms: Record<string, boolean> = {
  [AlgSHA256]: true,
  [AlgSHA384]: true,
  [AlgSHA512]: true,
};

const JWT_REGEX = /^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+(\.[A-Za-z0-9\-_]+)?$/;

export function isJWT(s: string): boolean {
  let trimmed = s.trim();
  if (trimmed.endsWith('.')) trimmed = trimmed.slice(0, -1);
  return JWT_REGEX.test(trimmed);
}

export function isSDJWT(raw: string): boolean {
  if (!raw) return false;
  let s = raw.trim();
  if (s.startsWith('"') && s.endsWith('"')) s = s.slice(1, -1);
  if (!s.includes('~')) return false;
  const idx = s.indexOf('~');
  return isJWT(s.slice(0, idx));
}

export function parse(raw: string): ParsedSDJWT {
  if (!isSDJWT(raw)) throw new Error('invalid SD-JWT format');
  let s = raw.trim();
  if (s.startsWith('"') && s.endsWith('"')) s = s.slice(1, -1);

  const parts = s.split('~');
  if (parts.length < 2) {
    throw new Error('invalid SD-JWT: missing disclosures or terminator');
  }

  const issuer = parts[0];

  const disclosures: string[] = [];
  for (let i = 1; i < parts.length; i++) {
    const seg = parts[i].trim();
    if (seg === '') continue;
    // Skip optional Key Binding JWT at the tail
    if (i === parts.length - 1 && isJWT(seg) && i > 1) {
      break;
    }
    disclosures.push(seg);
  }

  const decodedDisclosures = parseDisclosures(disclosures);

  return { baseJWT: issuer, disclosures, decodedDisclosures };
}

export function buildSDJWTPresentation(
  issuerSignedJWT: string,
  selectedDisclosures: string[],
): string {
  let out = issuerSignedJWT;
  for (const sel of selectedDisclosures) {
    if (!sel) continue;
    out += '~' + sel;
  }
  return out + '~';
}

export function decodeDisclosures(disclosures: string[]): DecodedDisclosure[] {
  return parseDisclosures(disclosures);
}

export function parseDisclosures(disclosures: string[]): DecodedDisclosure[] {
  const out: DecodedDisclosure[] = [];
  for (const disc of disclosures) {
    if (!disc) continue;
    const info = parseDisclosure(disc);
    out.push({
      disclosure: disc,
      salt: info.salt,
      fieldName: info.objectField,
      value: info.value,
      isArrayElem: info.isArrayElem,
    });
  }
  return out;
}

export function parseDisclosure(disc: string): DisclosureInfo {
  let decoded: Buffer;
  try {
    decoded = Buffer.from(disc, 'base64url');
  } catch {
    throw new Error(`failed to decode disclosure "${disc}"`);
  }

  let arr: unknown[];
  try {
    arr = JSON.parse(decoded.toString('utf8'));
  } catch (err) {
    throw new Error(
      `failed to unmarshal disclosure: ${(err as Error).message}`,
    );
  }
  if (!Array.isArray(arr)) {
    throw new Error('failed to unmarshal disclosure: not an array');
  }
  if (arr.length !== 2 && arr.length !== 3) {
    throw new Error(
      `invalid disclosure structure: expected 2 or 3 elements, got ${arr.length}`,
    );
  }

  const info: DisclosureInfo = {
    raw: disc,
    salt: '',
    array: arr,
    objectField: '',
    value: undefined,
    isArrayElem: false,
  };

  if (typeof arr[0] !== 'string') {
    throw new Error('disclosure salt must be a string');
  }
  info.salt = arr[0];

  if (arr.length === 3) {
    if (typeof arr[1] !== 'string') {
      throw new Error('disclosure field name must be a string');
    }
    info.objectField = arr[1];
    info.value = arr[2];
    info.isArrayElem = false;
  } else {
    info.value = arr[1];
    info.isArrayElem = true;
  }

  return info;
}

export function hashDisclosure(sdAlg: string, disclosure: string): string {
  const bytes = Buffer.from(disclosure, 'utf8');
  let digest: Uint8Array;
  switch (sdAlg) {
    case AlgSHA256:
      digest = sha256(bytes);
      break;
    case AlgSHA384:
      digest = sha384(bytes);
      break;
    case AlgSHA512:
      digest = sha512(bytes);
      break;
    default:
      throw new Error(`unsupported sd_alg "${sdAlg}"`);
  }
  return Buffer.from(digest).toString('base64url');
}

export function randomSalt(): string {
  return randomBytes(16).toString('base64url');
}
