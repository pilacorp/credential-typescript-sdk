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

  const rootCopy = deepCopyMap(vcMap);
  const processed = processNode(rootCopy, disclosureMap);
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
    out.set(h, info);
  }
  return out;
}

function processNode(
  node: unknown,
  disclosureMap: Map<string, DisclosureInfo>,
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

        const info = disclosureMap.get(h);
        if (!info) {
          out.push({ '...': h });
          continue;
        }
        if (!info.isArrayElem) {
          throw new Error('object field disclosure used in array context');
        }
        out.push(processNode(info.value, disclosureMap));
        continue;
      }
      out.push(processNode(elem, disclosureMap));
    }
    return out;
  }

  if (node && typeof node === 'object') {
    const obj = node as JSONMap;
    const rawSd = obj._sd;
    if (rawSd !== undefined) {
      const objectDigests = new Set<string>();
      let hashes: string[];
      if (Array.isArray(rawSd)) {
        hashes = (rawSd as unknown[]).filter(
          (x): x is string => typeof x === 'string',
        );
      } else {
        hashes = [];
      }
      applySDHashes(hashes, obj, disclosureMap, objectDigests);
      delete obj._sd;
    }
    for (const [k, v] of Object.entries(obj)) {
      obj[k] = processNode(v, disclosureMap);
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
): void {
  for (const h of hashes) {
    if (objectDigests.has(h)) {
      throw new Error(`duplicate digest "${h}" found in _sd array`);
    }
    objectDigests.add(h);

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

    v[info.objectField] = processNode(info.value, disclosureMap);
  }
}
