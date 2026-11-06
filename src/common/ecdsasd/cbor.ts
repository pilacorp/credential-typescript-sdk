/** Minimal CBOR for ecdsa-sd-2023 proof values (arrays, maps, bytes, strings, ints). */

function encodeHead(major: number, n: number): Uint8Array {
  if (n < 24) return Uint8Array.of((major << 5) | n);
  if (n < 256) return Uint8Array.of((major << 5) | 24, n);
  if (n < 65536) return Uint8Array.of((major << 5) | 25, n >> 8, n & 0xff);
  const b = Buffer.alloc(5);
  b[0] = (major << 5) | 26;
  b.writeUInt32BE(n, 1);
  return new Uint8Array(b);
}

function concat(chunks: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let o = 0;
  for (const c of chunks) {
    out.set(c, o);
    o += c.length;
  }
  return out;
}

export function cborEncode(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) {
    return concat([encodeHead(2, value.length), value]);
  }
  if (Buffer.isBuffer(value)) {
    return cborEncode(new Uint8Array(value));
  }
  if (typeof value === 'string') {
    const b = Buffer.from(value, 'utf8');
    return concat([encodeHead(3, b.length), new Uint8Array(b)]);
  }
  if (typeof value === 'number' && Number.isInteger(value)) {
    if (value >= 0) return encodeHead(0, value);
    const n = -1 - value;
    return encodeHead(1, n);
  }
  if (Array.isArray(value)) {
    return concat([encodeHead(4, value.length), ...value.map(cborEncode)]);
  }
  if (value instanceof Map) {
    const parts: Uint8Array[] = [encodeHead(5, value.size)];
    const entries = [...value.entries()].sort((a, b) => Number(a[0]) - Number(b[0]));
    for (const [k, v] of entries) {
      parts.push(cborEncode(k), cborEncode(v));
    }
    return concat(parts);
  }
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>);
    const parts: Uint8Array[] = [encodeHead(5, entries.length)];
    for (const [k, v] of entries) {
      parts.push(cborEncode(Number.isFinite(Number(k)) ? Number(k) : k), cborEncode(v));
    }
    return concat(parts);
  }
  throw new Error(`cbor: unsupported type ${typeof value}`);
}

export function cborDecode(data: Uint8Array): unknown {
  const { value, offset } = decodeAt(data, 0);
  if (offset !== data.length) {
    throw new Error('cbor: trailing bytes');
  }
  return value;
}

function decodeAt(data: Uint8Array, offset: number): { value: unknown; offset: number } {
  const b = data[offset];
  const major = b >> 5;
  let ai = b & 31;
  offset += 1;
  let n: number;
  if (ai < 24) n = ai;
  else if (ai === 24) {
    n = data[offset];
    offset += 1;
  } else if (ai === 25) {
    n = (data[offset] << 8) | data[offset + 1];
    offset += 2;
  } else if (ai === 26) {
    n = Number(Buffer.from(data.subarray(offset, offset + 4)).readUInt32BE(0));
    offset += 4;
  } else {
    throw new Error('cbor: additional info not supported');
  }
  if (major === 0) return { value: n, offset };
  if (major === 1) return { value: -1 - n, offset };
  if (major === 2) {
    const value = data.subarray(offset, offset + n);
    return { value: new Uint8Array(value), offset: offset + n };
  }
  if (major === 3) {
    const value = Buffer.from(data.subarray(offset, offset + n)).toString('utf8');
    return { value, offset: offset + n };
  }
  if (major === 4) {
    const arr: unknown[] = [];
    for (let i = 0; i < n; i++) {
      const next = decodeAt(data, offset);
      arr.push(next.value);
      offset = next.offset;
    }
    return { value: arr, offset };
  }
  if (major === 5) {
    const m = new Map<unknown, unknown>();
    for (let i = 0; i < n; i++) {
      const k = decodeAt(data, offset);
      const v = decodeAt(data, k.offset);
      m.set(k.value, v.value);
      offset = v.offset;
    }
    return { value: m, offset };
  }
  throw new Error(`cbor: major type ${major} not supported`);
}
