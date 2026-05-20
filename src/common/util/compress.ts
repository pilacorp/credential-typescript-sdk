/**
 * Gzip compression helpers — Node port of credential/common/util/compress.go
 */
import { gzipSync, gunzipSync } from 'zlib';

export function compress(data: Uint8Array): Uint8Array {
  return new Uint8Array(gzipSync(Buffer.from(data)));
}

export function decompress(data: Uint8Array): Uint8Array {
  return new Uint8Array(gunzipSync(Buffer.from(data)));
}

export function compressToBase64(data: Uint8Array): string {
  return Buffer.from(compress(data)).toString('base64');
}

export function decompressFromBase64(data: string): Uint8Array {
  return decompress(new Uint8Array(Buffer.from(data, 'base64')));
}

export function compressToBase64URL(data: Uint8Array): string {
  return Buffer.from(compress(data)).toString('base64url');
}

export function decompressFromBase64URL(data: string): Uint8Array {
  return decompress(new Uint8Array(Buffer.from(data, 'base64url')));
}
