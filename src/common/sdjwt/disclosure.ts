/**
 * Build SD-JWT disclosures at issuing time — Node port of
 * credential/common/sdjwt/disclosure.go
 *
 * Walks dot+[index] paths, hashes salted disclosures into `_sd` / `{"...": h}`
 * placeholders, optionally adds decoy hashes and shuffles the resulting arrays.
 */
import { randomBytes } from 'crypto';
import { deepCopyMap, JSONMap } from '../util/json';
import {
  DefaultHashAlgorithm,
  hashDisclosure,
  randomSalt,
  supportedHashAlgorithms,
} from './helper';
import { DecoyConfig, PathSegment, ResolvedTarget, TargetKind } from './types';

export interface BuildDisclosuresInput {
  vc: JSONMap;
  selectivePaths?: string[];
  hashAlgorithm?: string;
  shuffle?: boolean;
  decoys?: DecoyConfig[];
}

export interface SDJWTResult {
  processedVC: JSONMap;
  disclosures: string[];
}

export function buildDisclosures(input: BuildDisclosuresInput): SDJWTResult {
  const sdAlg = input.hashAlgorithm || DefaultHashAlgorithm;
  if (!supportedHashAlgorithms[sdAlg]) {
    throw new Error(`unsupported hash algorithm "${sdAlg}"`);
  }

  const processedVC = deepCopyMap(input.vc);
  const decoys = input.decoys ?? [];
  const selectivePaths = input.selectivePaths ?? [];

  if (decoys.length > 0) {
    processedVC._sd_alg = sdAlg;
  }

  if (selectivePaths.length === 0 && decoys.length === 0) {
    return { processedVC, disclosures: [] };
  }

  if (selectivePaths.length > 0) {
    processedVC._sd_alg = sdAlg;
  }

  const disclosures = processSelectivePaths(processedVC, selectivePaths, sdAlg);
  processDecoys(processedVC, decoys, sdAlg);

  if (input.shuffle) {
    shuffleSDArrays(processedVC);
  }

  return { processedVC, disclosures };
}

function processSelectivePaths(
  vc: JSONMap,
  paths: string[],
  sdAlg: string,
): string[] {
  const out: string[] = [];
  for (const raw of paths) {
    const path = raw.trim();
    if (!path) throw new Error('empty path');
    out.push(processSinglePath(vc, path, sdAlg));
  }
  return out;
}

function processSinglePath(vc: JSONMap, path: string, sdAlg: string): string {
  const resolved = resolvePath(vc, path);
  if (!resolved) throw new Error(`path "${path}" not found`);
  return buildAndApplyDisclosure(resolved, path, sdAlg);
}

function buildAndApplyDisclosure(
  resolved: ResolvedTarget,
  path: string,
  sdAlg: string,
): string {
  const salt = randomSalt();
  const disclosureArr = buildDisclosureArray(resolved, salt);
  const disclosureJSON = JSON.stringify(disclosureArr);
  const encodedDisclosure = Buffer.from(disclosureJSON, 'utf8').toString('base64url');
  const digest = hashDisclosure(sdAlg, encodedDisclosure);
  applyDisclosureToVC(resolved, digest);
  return encodedDisclosure;
}

function buildDisclosureArray(resolved: ResolvedTarget, salt: string): unknown[] {
  switch (resolved.kind) {
    case TargetKind.ObjectField:
    case TargetKind.ArrayContainer:
      return [salt, resolved.fieldName, resolved.value];
    case TargetKind.ArrayElem:
      return [salt, resolved.value];
  }
}

function applyDisclosureToVC(resolved: ResolvedTarget, digest: string): void {
  if (resolved.kind === TargetKind.ObjectField || resolved.kind === TargetKind.ArrayContainer) {
    const m = resolved.parent as JSONMap;
    appendSD(m, digest);
    delete m[resolved.fieldName];
    return;
  }
  if (resolved.kind === TargetKind.ArrayElem) {
    const arr = resolved.parent as unknown[];
    arr[resolved.index] = { '...': digest };
    return;
  }
  throw new Error(`unexpected kind "${resolved.kind}"`);
}

function processDecoys(
  vc: JSONMap,
  decoys: DecoyConfig[],
  sdAlg: string,
): void {
  for (const decoy of decoys) {
    if (decoy.count <= 0) continue;
    const hashes = generateDecoyHashes(sdAlg, decoy.count);
    applyDecoyToVC(vc, decoy.path, hashes);
  }
}

function applyDecoyToVC(vc: JSONMap, path: string, hashes: string[]): void {
  const resolved = resolvePath(vc, path);
  if (!resolved) return;
  switch (resolved.kind) {
    case TargetKind.ObjectField:
      applyDecoyToObjectField(resolved, hashes);
      return;
    case TargetKind.ArrayContainer:
      applyDecoyToArrayContainer(resolved, hashes);
      return;
    case TargetKind.ArrayElem:
      applyDecoyToArrayElement(resolved, hashes);
      return;
  }
}

function applyDecoyToObjectField(resolved: ResolvedTarget, hashes: string[]): void {
  let target: JSONMap;
  if (resolved.value && typeof resolved.value === 'object' && !Array.isArray(resolved.value)) {
    target = resolved.value as JSONMap;
  } else {
    target = resolved.parent as JSONMap;
  }
  for (const h of hashes) appendSD(target, h);
}

function applyDecoyToArrayContainer(resolved: ResolvedTarget, hashes: string[]): void {
  const arr = resolved.value as unknown[];
  const parentMap = resolved.parent as JSONMap;
  const newArr = [...arr];
  for (const h of hashes) newArr.push({ '...': h });
  parentMap[resolved.fieldName] = newArr;
}

function applyDecoyToArrayElement(resolved: ResolvedTarget, hashes: string[]): void {
  if (hashes.length === 0) return;
  const arr = resolved.parent as unknown[];
  for (const h of hashes) arr.push({ '...': h });
  resolved.parent = arr;
  if (resolved.parentMap && resolved.parentKey) {
    resolved.parentMap[resolved.parentKey] = arr;
  }
}

function appendSD(m: JSONMap, digest: string): void {
  const existing = m._sd;
  if (existing == null) {
    m._sd = [digest];
    return;
  }
  if (Array.isArray(existing)) {
    (existing as unknown[]).push(digest);
    return;
  }
}

function shuffleSDArrays(node: unknown): void {
  if (Array.isArray(node)) {
    for (const elem of node) shuffleSDArrays(elem);
    return;
  }
  if (node && typeof node === 'object') {
    const obj = node as JSONMap;
    const sd = obj._sd;
    if (Array.isArray(sd)) {
      const arr = [...sd];
      for (let i = arr.length - 1; i > 0; i--) {
        const j = randomInt(i + 1);
        [arr[i], arr[j]] = [arr[j], arr[i]];
      }
      obj._sd = arr;
    }
    for (const v of Object.values(obj)) shuffleSDArrays(v);
  }
}

function randomInt(upperExclusive: number): number {
  // crypto.randomInt(0, max) is exclusive on max. Use Math safely guarded.
  // Avoid Node v17+ specific API to remain compatible with bun/deno later.
  const buf = randomBytes(4).readUInt32BE(0);
  return buf % upperExclusive;
}

function generateDecoyHashes(sdAlg: string, count: number): string[] {
  const out: string[] = [];
  for (let i = 0; i < count; i++) {
    out.push(hashDisclosure(sdAlg, randomSalt()));
  }
  return out;
}

export function resolvePath(root: JSONMap, path: string): ResolvedTarget | null {
  if (path === '') {
    return {
      parent: root,
      kind: TargetKind.ObjectField,
      fieldName: '',
      index: 0,
      value: undefined,
    };
  }

  const segs = parsePath(path);
  if (segs.length === 0) {
    return {
      parent: root,
      kind: TargetKind.ObjectField,
      fieldName: '',
      index: 0,
      value: undefined,
    };
  }

  let current: unknown = root;

  for (let i = 0; i < segs.length; i++) {
    const seg = segs[i];
    const last = i === segs.length - 1;

    if (seg.index === undefined) {
      if (typeof current !== 'object' || current === null || Array.isArray(current)) {
        throw new Error(`segment "${seg.key}" expects object`);
      }
      const m = current as JSONMap;
      if (!(seg.key in m)) return null;
      const val = m[seg.key];
      if (last) {
        if (Array.isArray(val)) {
          return {
            parent: m,
            kind: TargetKind.ArrayContainer,
            fieldName: seg.key,
            index: 0,
            value: val,
          };
        }
        return {
          parent: m,
          kind: TargetKind.ObjectField,
          fieldName: seg.key,
          index: 0,
          value: val,
        };
      }
      current = val;
      continue;
    }

    const arr = resolveArray(current, seg);
    if (arr === null) return null;
    const idx = seg.index;
    if (idx < 0 || idx >= arr.length) {
      throw new Error(
        `index ${idx} out of range (len ${arr.length}) for path "${path}"`,
      );
    }
    if (last) {
      let parentMapRef: JSONMap | undefined;
      let parentKey = '';
      if (seg.key) {
        parentMapRef = current as JSONMap;
        parentKey = seg.key;
      }
      return {
        parent: arr,
        parentMap: parentMapRef,
        parentKey,
        kind: TargetKind.ArrayElem,
        fieldName: '',
        index: idx,
        value: arr[idx],
      };
    }
    current = arr[idx];
  }

  return null;
}

function resolveArray(current: unknown, seg: PathSegment): unknown[] | null {
  if (seg.key) {
    if (typeof current !== 'object' || current === null || Array.isArray(current)) {
      throw new Error(`segment "${seg.key}" expects object`);
    }
    const m = current as JSONMap;
    if (!(seg.key in m)) return null;
    const raw = m[seg.key];
    if (!Array.isArray(raw)) {
      throw new Error(`segment "${seg.key}" expects array`);
    }
    return raw;
  }
  if (!Array.isArray(current)) {
    throw new Error(`segment [${seg.index}] expects array`);
  }
  return current;
}

export function parsePath(path: string): PathSegment[] {
  const parts = path.split('.');
  const segs: PathSegment[] = [];

  for (const raw of parts) {
    const p = raw.trim();
    if (!p) continue;

    const bracketIdx = p.indexOf('[');
    if (bracketIdx === -1) {
      segs.push({ key: p });
      continue;
    }

    const key = p.slice(0, bracketIdx);
    const rest = p.slice(bracketIdx);
    if (!rest.endsWith(']')) {
      throw new Error(`invalid array segment "${p}" in path "${path}"`);
    }
    const idxStr = rest.slice(1, -1);
    if (idxStr === '') {
      throw new Error(`empty index in path "${path}"`);
    }
    if (idxStr === '*') {
      throw new Error(`wildcard index '*' is not supported in path "${path}"`);
    }
    const i = parseInt(idxStr, 10);
    if (Number.isNaN(i) || String(i) !== idxStr) {
      throw new Error(`invalid index "${idxStr}" in path "${path}"`);
    }
    segs.push({ key, index: i });
  }

  return segs;
}
