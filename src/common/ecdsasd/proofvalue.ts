import { cborDecode, cborEncode } from './cbor';

export const baseProofHeader = new Uint8Array([0xd9, 0x5d, 0x00]);
export const derivedProofHeader = new Uint8Array([0xd9, 0x5d, 0x01]);

export type SpecBaseProof = {
  baseSignature: Uint8Array;
  publicKey: Uint8Array;
  hmacKey: Uint8Array;
  signatures: Uint8Array[];
  mandatoryPointers: string[];
};

export type SpecDerivedProof = {
  baseSignature: Uint8Array;
  publicKey: Uint8Array;
  signatures: Uint8Array[];
  labelMap: Record<string, string>;
  mandatoryIndexes: number[];
};

export function serializeBaseProofValue(p: SpecBaseProof): string {
  const enc = cborEncode([
    p.baseSignature,
    p.publicKey,
    p.hmacKey,
    p.signatures,
    p.mandatoryPointers ?? [],
  ]);
  return multibaseProofValue(baseProofHeader, enc);
}

export function parseBaseProofValue(proofValue: string): SpecBaseProof {
  const raw = decodeProofValue(proofValue, baseProofHeader);
  const arr = cborDecode(raw) as unknown[];
  if (!Array.isArray(arr) || arr.length !== 5) {
    throw new Error(`ecdsasd: base proof value: want 5 elements, got ${Array.isArray(arr) ? arr.length : 0}`);
  }
  return {
    baseSignature: asBytes(arr[0]),
    publicKey: asBytes(arr[1]),
    hmacKey: asBytes(arr[2]),
    signatures: (arr[3] as unknown[]).map(asBytes),
    mandatoryPointers: arr[4] as string[],
  };
}

export function serializeDisclosureProofValue(p: SpecDerivedProof): string {
  const compressed = compressLabelMap(p.labelMap);
  const enc = cborEncode([
    p.baseSignature,
    p.publicKey,
    p.signatures,
    compressed,
    p.mandatoryIndexes.map((n) => n),
  ]);
  return multibaseProofValue(derivedProofHeader, enc);
}

export function parseDisclosureProofValue(proofValue: string): SpecDerivedProof {
  const raw = decodeProofValue(proofValue, derivedProofHeader);
  const arr = cborDecode(raw) as unknown[];
  if (!Array.isArray(arr) || arr.length !== 5) {
    throw new Error(`ecdsasd: derived proof value: want 5 elements, got ${Array.isArray(arr) ? arr.length : 0}`);
  }
  return {
    baseSignature: asBytes(arr[0]),
    publicKey: asBytes(arr[1]),
    signatures: (arr[2] as unknown[]).map(asBytes),
    labelMap: decompressLabelMap(arr[3] as Record<string, Uint8Array>),
    mandatoryIndexes: (arr[4] as number[]).map((n) => Number(n)),
  };
}

function compressLabelMap(labelMap: Record<string, string>): Map<number, Uint8Array> {
  const out = new Map<number, Uint8Array>();
  for (const [k, v] of Object.entries(labelMap)) {
    const num = Number.parseInt(k.replace(/^c14n/, ''), 10);
    const b = Buffer.from(v.replace(/^u/, ''), 'base64url');
    out.set(num, new Uint8Array(b));
  }
  return out;
}

function decompressLabelMap(compressed: Record<string, Uint8Array> | Map<unknown, unknown>): Record<string, string> {
  const out: Record<string, string> = {};
  const entries =
    compressed instanceof Map
      ? [...compressed.entries()].map(([k, v]) => [Number(k), v] as const)
      : Object.entries(compressed).map(([k, v]) => [Number(k), v] as const);
  entries.sort((a, b) => Number(a[0]) - Number(b[0]));
  for (const [k, v] of entries) {
    out[`c14n${k}`] = 'u' + Buffer.from(asBytes(v)).toString('base64url');
  }
  return out;
}

function multibaseProofValue(header: Uint8Array, payload: Uint8Array): string {
  const buf = new Uint8Array(header.length + payload.length);
  buf.set(header, 0);
  buf.set(payload, header.length);
  return 'u' + Buffer.from(buf).toString('base64url');
}

export function decodeProofValue(proofValue: string, header: Uint8Array): Uint8Array {
  if (!proofValue || proofValue[0] !== 'u') {
    throw new Error("ecdsasd: proof value must be base64url-no-pad multibase ('u')");
  }
  const raw = Buffer.from(proofValue.slice(1), 'base64url');
  for (let i = 0; i < header.length; i++) {
    if (raw[i] !== header[i]) throw new Error('ecdsasd: proof value has wrong header');
  }
  return new Uint8Array(raw.subarray(header.length));
}

function asBytes(v: unknown): Uint8Array {
  if (v instanceof Uint8Array) return v;
  if (Buffer.isBuffer(v)) return new Uint8Array(v);
  throw new Error('ecdsasd: expected bytes');
}
