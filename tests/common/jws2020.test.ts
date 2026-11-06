import { StaticResolver } from '../../src/common/verification-method';
import { generateKeyPairSync } from 'node:crypto';
import { p256 } from '@noble/curves/nist';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '../../src/common/crypto/hex';
import { canonicalize, verifyProof } from '../../src/common/jsonmap/jsonmap';
import { P256Provider } from '../../src/common/signer/p256-provider';
import type { DIDDocument, ResolverProvider } from '../../src/common/verification-method';

const ISSUER = 'did:example:jws';

async function attachAndVerify(
  alg: 'ES256' | 'RS256',
  sign: (signingInput: Uint8Array) => Uint8Array,
  jwk: Record<string, string>,
): Promise<void> {
  const body = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: ISSUER,
    credentialSubject: { id: 'did:example:subject' },
  };
  const payload = await canonicalize(body);
  const header = Buffer.from(
    JSON.stringify({ alg, b64: false, crit: ['b64'] }),
    'utf8',
  ).toString('base64url');
  const signingInput = Buffer.concat([Buffer.from(header, 'utf8'), Buffer.from('.'), Buffer.from(payload)]);
  const sig = sign(new Uint8Array(signingInput));
  const jws = `${header}..${Buffer.from(sig).toString('base64url')}`;
  const cred = {
    ...body,
    proof: {
      type: 'JsonWebSignature2020',
      created: '2020-01-01T00:00:00Z',
      verificationMethod: `${ISSUER}#key-1`,
      proofPurpose: 'assertionMethod',
      jws,
    },
  };
  const doc: DIDDocument = {
    '@context': [],
    id: ISSUER,
    verificationMethod: [
      {
        id: `${ISSUER}#key-1`,
        type: 'JsonWebKey2020',
        controller: ISSUER,
        publicKeyJwk: jwk as never,
      },
    ],
    authentication: [`${ISSUER}#key-1`],
    assertionMethod: [`${ISSUER}#key-1`],
  };
  await expect(verifyProof(cred, new StaticResolver(doc))).resolves.toBe(true);
}

describe('JsonWebSignature2020 verify-only', () => {
  it('verifies ES256 detached JWS', async () => {
    const priv = p256.utils.randomPrivateKey();
    const pub = p256.getPublicKey(priv, false);
    const x = Buffer.from(pub.subarray(1, 33)).toString('base64url');
    const y = Buffer.from(pub.subarray(33)).toString('base64url');
    const provider = new P256Provider(bytesToHex(priv));
    await attachAndVerify('ES256', (input) => provider.sign(sha256(input)), {
      kty: 'EC',
      crv: 'P-256',
      x,
      y,
    });
  });

  it('verifies RS256 detached JWS', async () => {
    const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwk = publicKey.export({ format: 'jwk' });
    const { sign } = await import('node:crypto');
    await attachAndVerify(
      'RS256',
      (input) => new Uint8Array(sign('sha256', Buffer.from(input), privateKey)),
      { kty: 'RSA', n: jwk.n as string, e: jwk.e as string },
    );
  });
});
