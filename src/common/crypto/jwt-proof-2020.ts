/**
 * Legacy JwtProof2020 verification — Node port of credential/common/crypto/jwt-proof-2020.go
 */
import { secp256k1 } from '@noble/curves/secp256k1';
import { verifySignature } from './crypto';
import { keyToBytes } from './hex';

export function verifyJwtProof(
  req: Record<string, unknown>,
  publicKeyHex: string,
): boolean {
  const proof = req.proof as Record<string, unknown> | undefined;
  if (!proof) throw new Error('JWT token is missing');
  const jwtToken = proof.jwt;
  if (typeof jwtToken !== 'string' || jwtToken === '') {
    throw new Error('JWT token is missing');
  }

  const { signature, message } = getSignatureAndMessage(jwtToken);

  const hexed = publicKeyHex.startsWith('0x') ? publicKeyHex : '0x' + publicKeyHex;
  // Like Go, compress the key first so 65-byte (04||X||Y) keys work too.
  const pubBytes = secp256k1.ProjectivePoint.fromHex(keyToBytes(hexed).slice(0)).toRawBytes(true);
  return verifySignature(pubBytes, message, signature);
}

function getSignatureAndMessage(jwtToken: string): {
  signature: Uint8Array;
  message: Uint8Array;
} {
  const parts = jwtToken.split('.');
  if (parts.length !== 3) {
    throw new Error('invalid JWT format');
  }
  const signature = Buffer.from(parts[2], 'base64url');
  const message = Buffer.from(parts[0] + '.' + parts[1], 'utf8');
  return { signature: new Uint8Array(signature), message: new Uint8Array(message) };
}
