import { deepCopy } from './copy';

export function parsePointer(pointer: string): Array<string | number> {
  let parts = pointer.split('/');
  if (parts.length > 0) parts = parts.slice(1);
  const parsed: Array<string | number> = [];
  for (const part of parts) {
    if (!part.includes('~')) {
      if (/^-?\d+$/.test(part)) {
        parsed.push(Number.parseInt(part, 10));
        continue;
      }
      parsed.push(part);
      continue;
    }
    parsed.push(part.replace(/~1/g, '/').replace(/~0/g, '~'));
  }
  return parsed;
}

export function selectJsonLd(
  document: Record<string, unknown>,
  pointers: string[],
): Record<string, unknown> | null {
  if (pointers.length === 0) return null;
  const sel: Record<string, unknown> = {};
  if ('@context' in document) sel['@context'] = deepCopy(document['@context']);
  initSelection(sel, document);
  for (const pointer of pointers) {
    const paths = parsePointer(pointer);
    if (paths.length === 0) return deepCopy(document);
    selectInto(document, paths, sel);
  }
  densifyArrays(sel);
  return sel;
}

function selectInto(source: unknown, paths: Array<string | number>, sel: unknown): unknown {
  if (paths.length === 0) {
    if (source && typeof source === 'object' && !Array.isArray(source)) {
      const merged: Record<string, unknown> = {
        ...(typeof sel === 'object' && sel && !Array.isArray(sel)
          ? (sel as Record<string, unknown>)
          : {}),
      };
      for (const [k, val] of Object.entries(source as Record<string, unknown>)) {
        merged[k] = deepCopy(val);
      }
      return merged;
    }
    if (Array.isArray(source)) return deepCopy(source);
    return source;
  }
  const path = paths[0];
  const childSource = getChild(source, path);
  if (childSource === undefined) {
    throw new Error('JSON pointer does not match document');
  }
  let childSel = getChild(sel, path);
  if (childSel === undefined) {
    childSel = Array.isArray(childSource)
      ? []
      : initSelection({}, childSource);
  }
  const newChild = selectInto(childSource, paths.slice(1), childSel);
  return setChild(sel, path, newChild);
}

function initSelection(sel: Record<string, unknown>, source: unknown): Record<string, unknown> {
  if (!source || typeof source !== 'object' || Array.isArray(source)) return sel;
  const m = source as Record<string, unknown>;
  if (typeof m.id === 'string' && !m.id.startsWith('_:')) sel.id = m.id;
  if ('type' in m) sel.type = m.type;
  return sel;
}

function getChild(parent: unknown, path: string | number): unknown {
  if (parent && typeof parent === 'object' && !Array.isArray(parent) && typeof path === 'string') {
    return (parent as Record<string, unknown>)[path];
  }
  if (Array.isArray(parent) && typeof path === 'number') {
    if (path < 0 || path >= parent.length) return undefined;
    return parent[path];
  }
  return undefined;
}

function setChild(parent: unknown, path: string | number, val: unknown): unknown {
  if (parent && typeof parent === 'object' && !Array.isArray(parent) && typeof path === 'string') {
    (parent as Record<string, unknown>)[path] = val;
    return parent;
  }
  if (Array.isArray(parent) && typeof path === 'number') {
    const p = parent;
    while (p.length <= path) p.push(null);
    p[path] = val;
    return p;
  }
  return parent;
}

function densifyArrays(v: unknown): unknown {
  if (v && typeof v === 'object' && !Array.isArray(v)) {
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
      (v as Record<string, unknown>)[k] = densifyArrays(val);
    }
    return v;
  }
  if (Array.isArray(v)) {
    return v.filter((e) => e !== null).map(densifyArrays);
  }
  return v;
}
