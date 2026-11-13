import { transform, transformToString } from '../../src/common/jsoncanonicalizer/jsoncanonicalizer';

describe('jsoncanonicalizer', () => {
  it('sorts object keys by UTF-16 code units', () => {
    const input = '{"b":1,"a":2,"c":{"y":1,"x":2}}';
    expect(transformToString(input)).toBe('{"a":2,"b":1,"c":{"x":2,"y":1}}');
  });

  it('formats numbers per ES6', () => {
    const input = '{"int":42,"float":1.5,"neg":-0}';
    expect(transformToString(input)).toBe('{"float":1.5,"int":42,"neg":0}');
  });

  it('escapes control characters', () => {
    const input = JSON.stringify({ s: 'a\nb' });
    const out = transformToString(input);
    expect(out).toBe('{"s":"a\\nb"}');
  });

  it('handles arrays without reordering', () => {
    const input = '[3,1,2]';
    expect(transformToString(input)).toBe('[3,1,2]');
  });

  it('rejects values that would otherwise serialize to wrong data', () => {
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    expect(() => transformToString({ d: new Date(0) })).toThrow(/plain JSON object/);
    expect(() => transformToString({ m: new Map() })).toThrow(/plain JSON object/);
    expect(() => transformToString([1, , 3])).toThrow(/sparse/); // eslint-disable-line no-sparse-arrays
    expect(() => transformToString({ u: undefined })).toThrow(/unsupported/);
    expect(() => transformToString(circular)).toThrow(/circular/);
  });

  it('caps nesting depth with an Error instead of overflowing the stack', () => {
    const nest = (n: number): unknown[] => {
      let v: unknown[] = [];
      for (let i = 1; i < n; i++) v = [v];
      return v;
    };
    expect(() => transformToString(nest(200))).not.toThrow();
    expect(() => transformToString(nest(201))).toThrow(/maximum depth/);
    expect(() => transformToString(nest(100_000))).toThrow(/maximum depth/);
  });

  it('accepts a Uint8Array, rejects invalid UTF-8, duplicate keys and scalars', () => {
    expect(new TextDecoder().decode(transform(new TextEncoder().encode('{"b":1,"a":"é"}')))).toBe('{"a":"é","b":1}');
    expect(transform('{}')).toBeInstanceOf(Uint8Array);
    expect(() => transform(new Uint8Array([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d]))).toThrow(/UTF-8/);
    expect(() => transform('{"a":1,"a":2}')).toThrow(/duplicate key/);
    expect(() => transform('1')).toThrow(/object or array/);
  });
});
