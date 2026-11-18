import { Code, DigitalCredentialError } from './errors';

export function checkAkaVCTs(v: unknown, vct: string): string[] {
  if (!Array.isArray(v) || v.length === 0) {
    throw new DigitalCredentialError(Code.Malformed, 'aka_vcts is not a non-empty array');
  }
  v.forEach((x, i) => {
    if (typeof x !== 'string' || x === '') {
      throw new DigitalCredentialError(Code.Malformed, `aka_vcts element ${i} is not a non-empty string`);
    }
    if (x === vct) throw new DigitalCredentialError(Code.Malformed, `aka_vcts element ${i} is the value of vct`);
  });
  return v as string[];
}
