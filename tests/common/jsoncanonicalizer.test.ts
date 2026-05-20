import { transformToString } from '../../src/common/jsoncanonicalizer/jsoncanonicalizer';

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
});
