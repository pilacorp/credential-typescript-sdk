import { getAddress } from 'ethers';

/** Go's common.IsHexAddress: 40 hex digits, optional 0x prefix, any case (no checksum rule). */
export function isHexAddress(s: string): boolean {
  return typeof s === 'string' && /^(0[xX])?[0-9a-fA-F]{40}$/.test(s);
}

/** Canonical checksummed form of a hex address of any case (what ethers APIs accept). */
export function toEthersAddress(s: string): string {
  if (!isHexAddress(s)) throw new Error(`invalid address: ${s}`);
  return getAddress(`0x${s.replace(/^0[xX]/, '').toLowerCase()}`);
}
