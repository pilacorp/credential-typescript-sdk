/**
 * Decodes base64url without padding (RFC 4648 §5, RFC 7515 §2) and refuses
 * every other spelling of the same bytes: padding, the standard alphabet,
 * characters outside the alphabet and non-zero pad bits (RFC 4648 §3.5).
 * Buffer.from skips or accepts all of these, so two strings would name one
 * value while a digest over the received string tells them apart.
 */
export function decodeBase64URLStrict(s: string): Buffer {
  const b = Buffer.from(s, 'base64url');
  if (!/^[A-Za-z0-9_-]*$/.test(s) || b.toString('base64url') !== s) throw new Error('invalid base64url');
  return b;
}
