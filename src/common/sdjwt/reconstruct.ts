/**
 * Reconstruct an SD-JWT payload from digests + disclosures — Node port of
 * credential/common/sdjwt/reconstruct.go
 */
import { deepCopyMap, hasOwn, JSONMap, setOwn } from '../util/json';
import {
  DefaultHashAlgorithm,
  hashDisclosure,
  isArrayPlaceholder,
  parseDisclosure,
  supportedHashAlgorithms,
} from './helper';
import { DisclosureInfo } from './types';

/** How one value of the payload was issued: in the clear, behind a digest that was opened, or still hidden. */
export interface IssuedNode {
  disclosed: boolean;
  hidden: boolean;
  hiddenFields: number;
  fields?: Record<string, IssuedNode>;
  elems?: IssuedNode[];
}

// Nesting of objects and arrays a strict read walks, disclosed values in place.
const maxDepth = 32;

/** Whether n, or anything inside it, came in a Disclosure. */
export function anyDisclosed(n: IssuedNode): boolean {
  return n.disclosed || Object.values(n.fields ?? {}).some(anyDisclosed) || (n.elems ?? []).some(anyDisclosed);
}

/**
 * strict applies the RFC 9901 rules on where "..." and _sd_alg may stand, and
 * bounds nesting. dc+sd-jwt reads strictly. The vc module does not: a VC
 * may carry those names as ordinary data.
 */

export function reconstruct(vcMap: JSONMap, disclosures: string[], validateAlg: boolean, strict = false): JSONMap {
  return reconstructIssued(vcMap, disclosures, validateAlg, strict).claims;
}

export function reconstructIssued(
  vcMap: JSONMap,
  disclosures: string[],
  validateAlg: boolean,
  strict = false,
): { claims: JSONMap; issued: IssuedNode } {
  const sdAlg = validateAndGetAlgorithm(vcMap, validateAlg);
  const disclosureMap = buildDisclosureMap(disclosures, sdAlg);
  const used = new Set<string>();

  const rootCopy = deepCopyMap(vcMap);
  const [processed, issued] = processNode(rootCopy, disclosureMap, used, 0, strict);
  for (const digest of disclosureMap.keys()) {
    if (!used.has(digest)) {
      throw new Error(`disclosure for digest "${digest}" matches nothing in the payload`);
    }
  }
  if (typeof processed !== 'object' || processed === null || Array.isArray(processed)) {
    throw new Error('processed payload is not an object');
  }
  const claims = processed as JSONMap;
  delete claims._sd_alg;
  if (issued.fields) delete issued.fields._sd_alg;
  return { claims, issued };
}

function validateAndGetAlgorithm(vcMap: JSONMap, validateAlg: boolean): string {
  let sdAlg = DefaultHashAlgorithm;
  if (typeof vcMap._sd_alg === 'string' && vcMap._sd_alg !== '') {
    sdAlg = vcMap._sd_alg;
  }
  if (validateAlg && !supportedHashAlgorithms[sdAlg]) {
    throw new Error(`unsupported _sd_alg: "${sdAlg}"`);
  }
  return sdAlg;
}

function buildDisclosureMap(
  disclosures: string[],
  sdAlg: string,
): Map<string, DisclosureInfo> {
  const out = new Map<string, DisclosureInfo>();
  for (const disc of disclosures) {
    if (!disc) continue;
    const h = hashDisclosure(sdAlg, disc);
    const info = parseDisclosure(disc);
    if (out.has(h)) throw new Error(`disclosure for digest "${h}" was sent more than once`);
    out.set(h, info);
  }
  return out;
}

function processNode(
  node: unknown,
  disclosureMap: Map<string, DisclosureInfo>,
  used: Set<string>,
  depth: number,
  strict: boolean,
): [unknown, IssuedNode] {
  if (strict && depth + 1 > maxDepth && node && typeof node === 'object') {
    throw new Error(`nesting deeper than ${maxDepth}`);
  }
  if (Array.isArray(node)) {
    const out: unknown[] = [];
    const elems: IssuedNode[] = [];
    const arrayDigests = new Set<string>();
    for (const elem of node) {
      if (isArrayPlaceholder(elem)) {
        const h = elem['...'];
        if (arrayDigests.has(h)) {
          throw new Error(`duplicate digest "${h}" found in array`);
        }
        arrayDigests.add(h);
        if (used.has(h)) throw new Error(`digest "${h}" is referenced more than once in the payload`);
        used.add(h);

        const info = disclosureMap.get(h);
        if (!info) {
          out.push({ '...': h });
          elems.push({ disclosed: false, hidden: true, hiddenFields: 0 });
          continue;
        }
        if (!info.isArrayElem) {
          throw new Error('object field disclosure used in array context');
        }
        const [v, n] = processNode(info.value, disclosureMap, used, depth + 1, strict);
        n.disclosed = true;
        out.push(v);
        elems.push(n);
        continue;
      }
      const [v, n] = processNode(elem, disclosureMap, used, depth + 1, strict);
      out.push(v);
      elems.push(n);
    }
    return [out, { disclosed: false, hidden: false, hiddenFields: 0, elems }];
  }

  if (node && typeof node === 'object') {
    const obj = node as JSONMap;
    // RFC 9901 §4.2.4.2: "..." is the one key of an array element placeholder
    // and nothing else. §4.1.1: _sd_alg is a top-level claim only.
    if (strict) {
      if (hasOwn(obj, '...')) throw new Error('"..." is in an object that is not an array element placeholder');
      if (depth > 0 && hasOwn(obj, '_sd_alg')) throw new Error('_sd_alg below the top level of the payload');
    }
    const rawSd = obj._sd;
    const issued: IssuedNode = { disclosed: false, hidden: false, hiddenFields: 0, fields: {} };
    for (const [k, v] of Object.entries(obj)) {
      if (k === '_sd') continue;
      const [nv, n] = processNode(v, disclosureMap, used, depth + 1, strict);
      setOwn(obj, k, nv);
      setOwn(issued.fields!, k, n);
    }
    if (rawSd !== undefined) {
      if (!Array.isArray(rawSd) || !rawSd.every((x): x is string => typeof x === 'string')) {
        throw new Error('_sd must be an array of digests');
      }
      applySDHashes(rawSd, obj, issued, disclosureMap, new Set<string>(), used, depth, strict);
      delete obj._sd;
    }
    return [obj, issued];
  }

  return [node, { disclosed: false, hidden: false, hiddenFields: 0 }];
}

function applySDHashes(
  hashes: string[],
  v: JSONMap,
  issued: IssuedNode,
  disclosureMap: Map<string, DisclosureInfo>,
  objectDigests: Set<string>,
  used: Set<string>,
  depth: number,
  strict: boolean,
): void {
  for (const h of hashes) {
    if (objectDigests.has(h)) {
      throw new Error(`duplicate digest "${h}" found in _sd array`);
    }
    objectDigests.add(h);
    if (used.has(h)) throw new Error(`digest "${h}" is referenced more than once in the payload`);
    used.add(h);

    const info = disclosureMap.get(h);
    if (!info) {
      issued.hiddenFields++;
      continue;
    }

    if (info.isArrayElem || info.objectField === '') {
      throw new Error('array element disclosure used in object context');
    }

    if (Object.prototype.hasOwnProperty.call(v, info.objectField)) {
      throw new Error(
        `duplicate field "${info.objectField}" when reconstructing SD-JWT object`,
      );
    }

    const [value, n] = processNode(info.value, disclosureMap, used, depth + 1, strict);
    n.disclosed = true;
    setOwn(v, info.objectField, value);
    setOwn(issued.fields!, info.objectField, n);
  }
}
