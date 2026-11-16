/**
 * JSON helpers — Node port of credential/common/util/json.go
 */

export type JSONMap = Record<string, unknown>;

export function hasOwn(obj: object, key: PropertyKey): boolean {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

/**
 * Sets obj[key] as an own property. A plain assignment of the key "__proto__"
 * would set the prototype of obj instead, and a JSON object may hold that key.
 */
export function setOwn(obj: object, key: string, value: unknown): void {
  Object.defineProperty(obj, key, { value, enumerable: true, writable: true, configurable: true });
}

export function shallowCopyObj(obj: JSONMap): JSONMap {
  return { ...obj };
}

export function deepCopyMap(src: JSONMap): JSONMap {
  return deepCopyValue(src) as JSONMap;
}

function isPlainObject(v: unknown): v is JSONMap {
  if (v === null || typeof v !== 'object') return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

function deepCopyValue(v: unknown): unknown {
  if (Array.isArray(v)) {
    return v.map(deepCopyValue);
  }
  if (isPlainObject(v)) {
    const out: JSONMap = {};
    for (const [k, val] of Object.entries(v)) {
      setOwn(out, k, deepCopyValue(val));
    }
    return out;
  }
  return v;
}

export function splitJSONObj(
  json: JSONMap,
  ...fields: string[]
): [JSONMap, JSONMap] {
  const fldsMap: JSONMap = {};
  const rest: JSONMap = {};
  for (const [k, v] of Object.entries(json)) {
    if (fields.includes(k)) {
      fldsMap[k] = v;
    } else {
      rest[k] = v;
    }
  }
  return [fldsMap, rest];
}

export function copyExcept(json: JSONMap, ...fields: string[]): JSONMap {
  const out = shallowCopyObj(json);
  for (const f of fields) delete out[f];
  return out;
}

export function selectFields(json: JSONMap, ...fields: string[]): JSONMap {
  const out: JSONMap = {};
  for (const f of fields) out[f] = json[f];
  return out;
}

export function mapSlice<T, U>(arr: T[], fn: (t: T) => U): U[] {
  return arr.map(fn);
}
