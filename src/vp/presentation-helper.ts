/**
 * VP helpers — Node port of vp/presentation_helper.go.
 */
import { JSONMap } from '../common/util/json';
import { formatRFC3339 } from '../common/util/time';
import { checkJwtTimeClaims, checkValidityPeriod, serializeContexts, serializeTypes } from '../common/util/vc';
import { parseCredential } from '../vc/credential';
import type { Credential } from '../vc/types';
import { didFromField } from '../common/jsonmap/jsonmap';
import { extractFieldFromMap } from '../vc/credential-helper';
import type { ResolvedPresentationOptions } from './options';
import type { PresentationContents, PresentationData } from './types';

export function parseStringField(obj: PresentationData, fieldName: string): string {
  const v = obj[fieldName];
  if (v === undefined) return '';
  if (typeof v !== 'string') {
    throw new Error(`field "${fieldName}" must be a string`);
  }
  return v;
}

export function checkExpiration(p: PresentationData, leewayMs = 0): void {
  checkValidityPeriod(p, 'presentation', leewayMs);
}

export { checkJwtTimeClaims };

export { extractFieldFromMap };

/**
 * Verifies each embedded credential (go verifyCredentials): the presentation's
 * resolver and leeway first, then the caller's validateVC options, which win.
 * Proof-only by default.
 */
export async function verifyCredentials(
  jsonPresentation: PresentationData,
  options: ResolvedPresentationOptions,
): Promise<void> {
  const contents = await parsePresentationContents(jsonPresentation);
  const vcs = contents.verifiableCredentials ?? [];
  if (vcs.length === 0) throw new Error('credential input is empty');
  for (let i = 0; i < vcs.length; i++) {
    const v = vcs[i];
    if (!v) throw new Error(`credential at index ${i} is nil`);
    try {
      await v.verify({
        resolver: options.resolver,
        clockSkewLeewayMs: options.clockSkewLeewayMs,
        ...options.vcOpts,
      });
    } catch (err) {
      throw new Error(`failed to verify credential at index ${i}: ${(err as Error).message}`);
    }
  }
}

export async function serializePresentationContents(
  vpc: PresentationContents | null,
): Promise<PresentationData> {
  if (!vpc) throw new Error('presentation contents is nil');
  if (
    (!vpc.context || vpc.context.length === 0) &&
    !vpc.id &&
    !vpc.holder
  ) {
    throw new Error('contents must have context, ID, or holder');
  }

  const vpJSON: PresentationData = {};
  if (vpc.context && vpc.context.length > 0) {
    vpJSON['@context'] = serializeContexts(vpc.context);
  }
  if (vpc.id) vpJSON.id = vpc.id;
  if (vpc.types && vpc.types.length > 0) {
    vpJSON.type = serializeTypes(vpc.types);
  }
  if (vpc.holder) vpJSON.holder = vpc.holder;
  if (vpc.validFrom) vpJSON.validFrom = formatRFC3339(vpc.validFrom);
  if (vpc.validUntil) vpJSON.validUntil = formatRFC3339(vpc.validUntil);

  if (vpc.verifiableCredentials && vpc.verifiableCredentials.length > 0) {
    const list: unknown[] = [];
    for (let i = 0; i < vpc.verifiableCredentials.length; i++) {
      const vc = vpc.verifiableCredentials[i];
      if (!vc) throw new Error(`credential at index ${i} is nil`);
      // Building a presentation does not verify its credentials (go parity):
      // pass validateVC to verify them, with the resolver you choose.
      list.push(await vc.serialize());
    }
    vpJSON.verifiableCredential = list;
  }
  return vpJSON;
}

export async function parsePresentationContents(
  vp: PresentationData,
): Promise<PresentationContents> {
  const contents: PresentationContents = {};

  if (Array.isArray(vp['@context'])) {
    contents.context = [];
    for (const ctx of vp['@context'] as unknown[]) {
      if (typeof ctx === 'string' || (ctx && typeof ctx === 'object' && !Array.isArray(ctx))) {
        contents.context.push(ctx);
      } else {
        throw new Error('unsupported context type');
      }
    }
  }
  if (typeof vp.id === 'string') contents.id = vp.id;
  if (typeof vp.type === 'string') contents.types = [vp.type];
  else if (Array.isArray(vp.type)) {
    contents.types = (vp.type as unknown[]).filter((t): t is string => typeof t === 'string');
  } else if (vp.type !== undefined) {
    throw new Error('unsupported type field');
  }
  const holder = didFromField(vp.holder);
  if (holder) contents.holder = holder;
  if (typeof vp.validFrom === 'string') {
    contents.validFrom = new Date(vp.validFrom);
    if (isNaN(contents.validFrom.getTime())) throw new Error('failed to parse validFrom');
  }
  if (typeof vp.validUntil === 'string') {
    contents.validUntil = new Date(vp.validUntil);
    if (isNaN(contents.validUntil.getTime())) throw new Error('failed to parse validUntil');
  }
  // verifiableCredential may be a single credential or an array of them.
  const embedded = vp.verifiableCredential;
  if (embedded !== undefined && embedded !== null) {
    contents.verifiableCredentials = await parseEmbeddedCredentials(
      Array.isArray(embedded) ? embedded : [embedded],
    );
  }
  return contents;
}

async function parseEmbeddedCredentials(items: unknown[]): Promise<Credential[]> {
  const out: Credential[] = [];
  for (let i = 0; i < items.length; i++) {
    const entry = items[i];
    if (entry == null) throw new Error(`credential at index ${i} is nil`);
    if (typeof entry === 'string') {
      out.push(await parseCredential(entry));
    } else if (typeof entry === 'object') {
      out.push(await parseCredential(JSON.stringify(entry)));
    } else {
      throw new Error(`unsupported credential entry at index ${i}`);
    }
  }
  return out;
}

export function isJWTPresentation(valStr: string): boolean {
  const trimmed = valStr.replace(/^"|"$/g, '');
  return /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/.test(trimmed);
}

export function isJSONPresentationBytes(raw: Uint8Array | string): boolean {
  const str = typeof raw === 'string' ? raw : Buffer.from(raw).toString('utf8');
  try {
    const parsed = JSON.parse(str.trim());
    return !!parsed && typeof parsed === 'object' && !Array.isArray(parsed);
  } catch {
    return false;
  }
}

export type { JSONMap };

/** A token that is not a plain JWT but has a JWT before its first "~" (SD-JWT shape). */
export function isSDJWTShaped(valStr: string): boolean {
  const trimmed = valStr.replace(/^"|"$/g, '');
  const i = trimmed.indexOf('~');
  return i >= 0 && isJWTPresentation(trimmed.slice(0, i));
}
