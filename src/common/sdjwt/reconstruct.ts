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

export function reconstruct(
  vcMap: JSONMap,
  disclosures: string[],
  validateAlg: boolean,
): JSONMap {
  const sdAlg = validateAndGetAlgorithm(vcMap, validateAlg);
  const disclosureMap = buildDisclosureMap(disclosures, sdAlg);
  const used = new Set<string>();

  const rootCopy = deepCopyMap(vcMap);
  const processed = processNode(rootCopy, disclosureMap, used);
  for (const digest of disclosureMap.keys()) {
    if (!used.has(digest)) {
      throw new Error(`disclosure for digest "${digest}" matches nothing in the payload`);
    }
  }
  if (typeof processed !== 'object' || processed === null || Array.isArray(processed)) {
    throw new Error('processed payload is not an object');
  }
  const result = processed as JSONMap;
  delete result._sd_alg;
  return result;
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
): unknown {
  if (Array.isArray(node)) {
    const out: unknown[] = [];
    const arrayDigests = new Set<string>();
    for (const elem of node) {
      // Placeholder { "...": h }
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
          continue;
        }
        if (!info.isArrayElem) {
          throw new Error('object field disclosure used in array context');
        }
        out.push(processNode(info.value, disclosureMap, used));
        continue;
      }
      out.push(processNode(elem, disclosureMap, used));
    }
    return out;
  }

  if (node && typeof node === 'object') {
    const obj = node as JSONMap;
    const rawSd = obj._sd;
    for (const [k, v] of Object.entries(obj)) {
      if (k !== '_sd') obj[k] = processNode(v, disclosureMap, used);
    }
    if (rawSd !== undefined) {
      if (!Array.isArray(rawSd) || !rawSd.every((x): x is string => typeof x === 'string')) {
        throw new Error('_sd must be an array of digests');
      }
      applySDHashes(rawSd, obj, disclosureMap, new Set<string>(), used);
      delete obj._sd;
    }
    return obj;
  }

  return node;
}

function applySDHashes(
  hashes: string[],
  v: JSONMap,
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
    if (!info) continue;

    if (info.isArrayElem || info.objectField === '') {
      throw new Error('array element disclosure used in object context');
    }

    if (info.objectField in v) {
      throw new Error(
        `duplicate field "${info.objectField}" when reconstructing SD-JWT object`,
      );
    }

    v[info.objectField] = processNode(info.value, disclosureMap, used);
  }
}
