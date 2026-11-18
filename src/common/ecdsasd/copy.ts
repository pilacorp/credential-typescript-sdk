export function deepCopy<T>(v: T): T {
  if (Array.isArray(v)) return v.map((item) => deepCopy(item)) as T;
  if (v && typeof v === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
      out[k] = deepCopy(val);
    }
    return out as T;
  }
  return v;
}
