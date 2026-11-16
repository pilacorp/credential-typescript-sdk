/**
 * Build SD-JWT disclosures at issuing time — Node port of
 * credential/common/sdjwt/disclosure.go
 *
 * Walks dot+[index] paths, hashes salted disclosures into `_sd` / `{"...": h}`
 * placeholders, optionally adds decoy hashes and shuffles the resulting arrays.
 */
import { randomBytes } from 'crypto';
import { deepCopyMap, hasOwn, JSONMap } from '../util/json';
import {
  DefaultHashAlgorithm,
  hashDisclosure,
  isArrayPlaceholder,
  randomSalt,
  supportedHashAlgorithms,
} from './helper';
import { DecoyConfig, PathSegment, ResolvedTarget, TargetKind } from './types';

export interface BuildDisclosuresInput {
  vc: JSONMap;
  selectivePaths?: string[];
  selectivePathSegments?: Array<Array<string | number>>;
  hashAlgorithm?: string;
  shuffle?: boolean;
  decoys?: DecoyConfig[];
  /**
   * Pads every object's _sd and every array's {"...": digest} placeholders
   * with decoy digests up to this count, in the payload and in the values of
   * the disclosures made from selectivePathSegments (RFC 9901 §4.2.5).
   */
  minDigests?: number;
  /**
   * Keeps minDigests decoys out of arrays. A receiver cannot tell an array
   * decoy from a hidden element, so a decoy moves the index of every element
   * after it.
   */
  noArrayDecoys?: boolean;
}

// The decoys minDigests may write: objects and arrays × minDigests.
const maxDecoys = 20000;

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
  // Read before _sd_alg is written, so no path can name it.
  checkPathSegments(processedVC, input.selectivePathSegments ?? []);

  if (decoys.length > 0) {
    processedVC._sd_alg = sdAlg;
  }

  const segmentPaths = input.selectivePathSegments ?? [];
  if (selectivePaths.length === 0 && decoys.length === 0 && segmentPaths.length === 0) {
    return { processedVC, disclosures: [] };
  }

  if (selectivePaths.length > 0 || segmentPaths.length > 0) {
    processedVC._sd_alg = sdAlg;
  }

  const minDigests = input.minDigests ?? 0;
  const noArrayDecoys = Boolean(input.noArrayDecoys);
  if (minDigests > 0) {
    const containers = countContainers(input.vc);
    if (containers > Math.floor(maxDecoys / minDigests)) {
      throw new Error(
        `${containers} objects and arrays × minDigests ${minDigests} is over ${maxDecoys} decoy digests`,
      );
    }
  }
  // A concealed value is complete before it is hashed into its disclosure:
  // nothing can pad it or reorder its _sd afterwards.
  const finish = (value: unknown): void => {
    padMinDigests(value, minDigests, sdAlg, noArrayDecoys);
    if (input.shuffle) shuffleSDArrays(value);
  };
  const fromSegments = processSelectivePathSegments(processedVC, segmentPaths, sdAlg, finish);
  const fromStrings = processSelectivePaths(processedVC, selectivePaths, sdAlg);
  const disclosures = [...fromSegments, ...fromStrings];
  processDecoys(processedVC, decoys, sdAlg);
  padMinDigests(processedVC, minDigests, sdAlg, noArrayDecoys);

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

function processSelectivePathSegments(
  vc: JSONMap,
  paths: Array<Array<string | number>>,
  sdAlg: string,
  finish: (value: unknown) => void,
): string[] {
  const out: string[] = [];
  for (const path of paths) {
    const resolved = resolvePathSegments(vc, path);
    if (!resolved) throw new Error(`path ${JSON.stringify(path)} not found`);
    finish(resolved.value);
    out.push(buildAndApplyDisclosure(resolved, JSON.stringify(path), sdAlg));
  }
  return out;
}

// Every path is read on the claims as given, before anything is written: a
// path then never names what this module adds, such as _sd or _sd_alg.
function checkPathSegments(vc: JSONMap, paths: Array<Array<string | number>>): void {
  const seen = new Set<string>();
  for (const path of paths) {
    if (!path.length) throw new Error('empty path');
    const key = JSON.stringify(path);
    if (seen.has(key)) throw new Error(`path ${key} given twice`);
    seen.add(key);
    if (!resolvePathSegments(vc, path)) throw new Error(`path ${key} does not exist in the claims`);
  }
}

function countContainers(v: unknown): number {
  if (!v || typeof v !== 'object') return 0;
  let n = 1;
  for (const child of Array.isArray(v) ? v : Object.values(v)) n += countContainers(child);
  return n;
}

function padMinDigests(root: unknown, min: number, sdAlg: string, noArrayDecoys: boolean): void {
  if (min <= 0) return;
  const walk = (n: unknown): void => {
    if (Array.isArray(n)) {
      n.forEach(walk);
      if (noArrayDecoys) return;
      // A decoy goes at a random position: decoys at the end would mark the
      // placeholders before them as real.
      for (let count = n.filter(isArrayPlaceholder).length; count < min; count++) {
        n.splice(randomInt(n.length + 1), 0, { '...': hashDisclosure(sdAlg, randomSalt()) });
      }
      return;
    }
    if (n && typeof n === 'object') {
      const o = n as JSONMap;
      if (isArrayPlaceholder(o)) return;
      for (const [k, v] of Object.entries(o)) if (k !== '_sd') walk(v);
      const sd: unknown[] = Array.isArray(o._sd) ? o._sd : [];
      while (sd.length < min) sd.push(hashDisclosure(sdAlg, randomSalt()));
      o._sd = sd;
    }
  };
  walk(root);
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

export function resolvePathSegments(root: JSONMap, path: Array<string | number>): ResolvedTarget | null {
  if (!path.length) return null;
  let current: unknown = root;
  for (let i = 0; i < path.length; i++) {
    const last = i === path.length - 1;
    const seg = path[i];
    if (typeof seg === 'string') {
      if (typeof current !== 'object' || current === null || Array.isArray(current)) {
        throw new Error(`segment ${JSON.stringify(seg)} expects object`);
      }
      const m = current as JSONMap;
      if (!hasOwn(m, seg)) return null;
      const val = m[seg];
      if (last) {
        if (Array.isArray(val)) {
          return { parent: m, kind: TargetKind.ArrayContainer, fieldName: seg, index: 0, value: val };
        }
        return { parent: m, kind: TargetKind.ObjectField, fieldName: seg, index: 0, value: val };
      }
      current = val;
      continue;
    }
    if (!Number.isInteger(seg) || seg < 0) throw new Error(`invalid index ${seg}`);
    if (!Array.isArray(current)) throw new Error(`segment [${seg}] expects array`);
    if (seg >= current.length) throw new Error(`index ${seg} out of range (len ${current.length})`);
    if (last) {
      return {
        parent: current,
        kind: TargetKind.ArrayElem,
        fieldName: '',
        index: seg,
        value: current[seg],
      };
    }
    current = current[seg];
  }
  return null;
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
      if (!hasOwn(m, seg.key)) return null;
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
    if (!hasOwn(m, seg.key)) return null;
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
