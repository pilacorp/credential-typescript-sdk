import { sha256 } from '@noble/hashes/sha256';
import { DigitalCredentialError, Code } from './errors';

const MAX_BYTES = 1 << 20;
const MAX_DISCLOSURES = 1000;

export function splitSDJWT(compact: string): {
  issuerJWT: string;
  disclosures: string[];
  kbJWT: string;
} {
  if (compact.length > MAX_BYTES) {
    throw new DigitalCredentialError(Code.Malformed, `SD-JWT of ${compact.length} bytes, at most ${MAX_BYTES}`);
  }
  const tildes = compact.split('~').length - 1;
  if (tildes === 0) {
    throw new DigitalCredentialError(Code.Malformed, 'sdjwt: no ~ separator');
  }
  if (tildes - 1 > MAX_DISCLOSURES) {
    throw new DigitalCredentialError(Code.Malformed, `too many disclosures`);
  }
  const parts = compact.split('~');
  const issuerJWT = parts[0];
  const kbJWT = parts[parts.length - 1];
  if (!isCompactJWS(issuerJWT)) {
    throw new DigitalCredentialError(Code.Malformed, 'Issuer-signed JWT is not three non-empty dot-separated parts');
  }
  if (kbJWT !== '' && !isCompactJWS(kbJWT)) {
    throw new DigitalCredentialError(Code.Malformed, 'the part after the last ~ is not a JWT (missing trailing ~?)');
  }
  const disclosures = parts.slice(1, -1);
  const seen = new Set<string>();
  disclosures.forEach((d, i) => {
    if (!d) throw new DigitalCredentialError(Code.Malformed, `empty disclosure at position ${i + 1}`);
    if (seen.has(d)) throw new DigitalCredentialError(Code.Malformed, `disclosure given twice`);
    seen.add(d);
  });
  return { issuerJWT, disclosures, kbJWT };
}

function isCompactJWS(s: string): boolean {
  const parts = s.split('.');
  return parts.length === 3 && parts.every((p) => p.length > 0);
}

export function sdHash(sdJWT: string): string {
  return Buffer.from(sha256(Buffer.from(sdJWT, 'utf8'))).toString('base64url');
}
