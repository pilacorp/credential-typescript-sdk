/**
 * Reconstruct an SD-JWT payload from digests + disclosures — Node port of
 * credential/common/sdjwt/reconstruct.go
 */
import { deepCopyMap, JSONMap } from '../util/json';
import {
  DefaultHashAlgorithm,
  hashDisclosure,
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

export function reconstruct(vcMap: JSONMap, disclosures: string[], validateAlg: boolean): JSONMap {
  return reconstructIssued(vcMap, disclosures, validateAlg).claims;
}

export function reconstructIssued(
  vcMap: JSONMap,
  disclosures: string[],
  validateAlg: boolean,
): { claims: JSONMap; issued: IssuedNode } {
  const sdAlg = validateAndGetAlgorithm(vcMap, validateAlg);
  const disclosureMap = buildDisclosureMap(disclosures, sdAlg);
  const used = new Set<string>();

  const rootCopy = deepCopyMap(vcMap);
  const [processed, issued] = processNode(rootCopy, disclosureMap, used);
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
): [unknown, IssuedNode] {
  if (Array.isArray(node)) {
    const out: unknown[] = [];
    const elems: IssuedNode[] = [];
    const arrayDigests = new Set<string>();
    for (const elem of node) {
      if (
        elem &&
        typeof elem === 'object' &&
        !Array.isArray(elem) &&
        Object.keys(elem as JSONMap).length === 1 &&
        typeof (elem as JSONMap)['...'] === 'string'
      ) {
        const h = (elem as JSONMap)['...'] as string;
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
        const [v, n] = processNode(info.value, disclosureMap, used);
        n.disclosed = true;
        out.push(v);
        elems.push(n);
        continue;
      }
      const [v, n] = processNode(elem, disclosureMap, used);
      out.push(v);
      elems.push(n);
    }
    return [out, { disclosed: false, hidden: false, hiddenFields: 0, elems }];
  }

  if (node && typeof node === 'object') {
    const obj = node as JSONMap;
    const rawSd = obj._sd;
    const issued: IssuedNode = { disclosed: false, hidden: false, hiddenFields: 0, fields: {} };
    for (const [k, v] of Object.entries(obj)) {
      if (k === '_sd') continue;
      const [nv, n] = processNode(v, disclosureMap, used);
      obj[k] = nv;
      issued.fields![k] = n;
    }
    if (rawSd !== undefined) {
      if (!Array.isArray(rawSd) || !rawSd.every((x): x is string => typeof x === 'string')) {
        throw new Error('_sd must be an array of digests');
      }
      applySDHashes(rawSd, obj, issued, disclosureMap, new Set<string>(), used);
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

    const [value, n] = processNode(info.value, disclosureMap, used);
    n.disclosed = true;
    v[info.objectField] = value;
    issued.fields![info.objectField] = n;
  }
}
