import { createHmac, randomBytes } from 'node:crypto';
import {
  canonicalizeNQuadsWithIdMap,
  compactJSONLD,
  expandJSONLD,
  toRDFNQuads,
} from '../processor/processor';
import { deepCopy } from './copy';
import { selectJsonLd } from './pointer';

const urnBnidRe = /<urn:bnid:([^>]+)>/g;
const bnodeRe = /_:([^\s]+)/g;

class SkolemLabeler {
  count = 0;
  constructor(
    readonly prefix: string,
    readonly random: string,
  ) {}
}

function skolemizeExpanded(expanded: unknown[], l: SkolemLabeler): unknown[] {
  const out: unknown[] = [];
  for (const element of expanded) {
    if (!element || typeof element !== 'object' || Array.isArray(element)) {
      out.push(deepCopy(element));
      continue;
    }
    const m = element as Record<string, unknown>;
    if ('@value' in m) {
      out.push(deepCopy(element));
      continue;
    }
    const node: Record<string, unknown> = {};
    for (const [prop, value] of Object.entries(m)) {
      node[prop] = Array.isArray(value)
        ? skolemizeExpanded(value, l)
        : skolemizeExpanded([value], l)[0];
    }
    const id = node['@id'];
    if (typeof id !== 'string') {
      node['@id'] = `${l.prefix}_${l.random}_${l.count}`;
      l.count += 1;
    } else if (id.startsWith('_:')) {
      node['@id'] = l.prefix + id.slice(2);
    }
    out.push(node);
  }
  return out;
}

async function skolemizeCompactJsonLd(
  document: Record<string, unknown>,
): Promise<{ expanded: unknown[]; compact: Record<string, unknown> }> {
  const expanded = await expandJSONLD(document);
  const labeler = new SkolemLabeler('urn:bnid:', randomBytes(16).toString('hex'));
  const skolemized = skolemizeExpanded(expanded, labeler);
  const compact = await compactJSONLD(skolemized, document['@context']);
  return { expanded: skolemized, compact };
}

function deskolemizeNQuads(nquads: string[]): string[] {
  return nquads.map((nq) =>
    nq.includes('<urn:bnid:') ? nq.replace(urnBnidRe, '_:$1') : nq,
  );
}

async function toDeskolemizedNQuads(document: unknown): Promise<string[]> {
  return deskolemizeNQuads(await toRDFNQuads(document));
}

export function relabelBlankNodes(nquads: string[], labelMap: Record<string, string>): string[] {
  return nquads.map((nq) =>
    nq.replace(bnodeRe, (match, label: string) => {
      const nl = labelMap[label];
      return nl ? `_:${nl}` : match;
    }),
  );
}

function createHmacLabelMap(
  canonicalIdMap: Record<string, string>,
  hmacKey: Uint8Array,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [input, c14n] of Object.entries(canonicalIdMap)) {
    const mac = createHmac('sha256', Buffer.from(hmacKey)).update(c14n).digest();
    out[input] = 'u' + Buffer.from(mac).toString('base64url');
  }
  return out;
}

async function labelReplacementCanonicalizeNQuads(
  nquads: string[],
  hmacKey: Uint8Array,
): Promise<{ nquads: string[]; labelMap: Record<string, string> }> {
  const [canonicalNQuads, rawIDMap] = await canonicalizeNQuadsWithIdMap(nquads);
  const canonicalIDMap: Record<string, string> = {};
  for (const [k, v] of rawIDMap.entries()) {
    canonicalIDMap[k.replace(/^_:/, '')] = v.replace(/^_:/, '');
  }
  const labelMap = createHmacLabelMap(canonicalIDMap, hmacKey);
  const c14nToNew: Record<string, string> = {};
  for (const [input, newLabel] of Object.entries(labelMap)) {
    c14nToNew[canonicalIDMap[input]] = newLabel;
  }
  const out = relabelBlankNodes(canonicalNQuads, c14nToNew);
  out.sort();
  return { nquads: out, labelMap };
}

async function selectCanonicalNQuads(
  compact: Record<string, unknown>,
  pointers: string[],
  labelMap: Record<string, string>,
): Promise<{ deskolemized: string[]; relabeled: string[] }> {
  const selection = selectJsonLd(compact, pointers);
  if (!selection) return { deskolemized: [], relabeled: [] };
  const deskolemized = await toDeskolemizedNQuads(selection);
  return { deskolemized, relabeled: relabelBlankNodes(deskolemized, labelMap) };
}

export type GroupIndexes = {
  matching: Map<number, string>;
  nonMatching: Map<number, string>;
  deskolemizedNQuads: string[];
};

export type GroupedCanon = {
  hmacNQuads: string[];
  labelMap: Record<string, string>;
  skolemizedCompact: Record<string, unknown>;
  groups: Record<string, GroupIndexes>;
};

export async function canonicalizeAndGroup(
  document: Record<string, unknown>,
  hmacKey: Uint8Array,
  groups: Record<string, string[]>,
): Promise<GroupedCanon> {
  const { expanded, compact } = await skolemizeCompactJsonLd(document);
  const deskolemized = await toDeskolemizedNQuads(expanded);
  const { nquads: hmacNQuads, labelMap } = await labelReplacementCanonicalizeNQuads(
    deskolemized,
    hmacKey,
  );
  const result: GroupedCanon = {
    hmacNQuads,
    labelMap,
    skolemizedCompact: compact,
    groups: {},
  };
  for (const [name, pointers] of Object.entries(groups)) {
    const selected = await selectCanonicalNQuads(compact, pointers, labelMap);
    const selSet = new Set(selected.relabeled);
    const gi: GroupIndexes = {
      matching: new Map(),
      nonMatching: new Map(),
      deskolemizedNQuads: selected.deskolemized,
    };
    hmacNQuads.forEach((nq, idx) => {
      if (selSet.has(nq)) gi.matching.set(idx, nq);
      else gi.nonMatching.set(idx, nq);
    });
    result.groups[name] = gi;
  }
  return result;
}

export function sortedIndexes(m: Map<number, string>): number[] {
  return [...m.keys()].sort((a, b) => a - b);
}

export function orderedValues(m: Map<number, string>): string[] {
  return sortedIndexes(m).map((k) => m.get(k)!);
}

export function hashMandatory(matching: Map<number, string>): Uint8Array {
  const { sha256 } = require('@noble/hashes/sha256') as typeof import('@noble/hashes/sha256');
  let buf = Buffer.alloc(0);
  for (const i of sortedIndexes(matching)) {
    buf = Buffer.concat([buf, Buffer.from(matching.get(i)!, 'utf8')]);
  }
  return sha256(buf);
}
