import { p256 } from '@noble/curves/nist';
import { P256Provider } from '../../src/common/signer/p256-provider';
import { bytesToHex } from '../../src/common/crypto/hex';
import {
  issue,
  parse,
  StaticResolver,
} from '../../src/digitalcredential';

describe('digitalcredential (IETF dc+sd-jwt)', () => {
  it('issues, presents one claim with a KB-JWT, and verifies', async () => {
    const issuerPriv = p256.utils.randomPrivateKey();
    const holderPriv = p256.utils.randomPrivateKey();
    const issuerPub = p256.getPublicKey(issuerPriv, false);
    const holderPub = p256.getPublicKey(holderPriv, false);
    const iss = 'https://issuer.example';
    const verifier = 'https://verifier.example';
    const nonce = 'n-0S6_WzA2Mj';

    const cred = await issue(
      {
        issuer: iss,
        vct: 'https://credentials.example/identity_credential',
        issuedAt: new Date(),
        expiry: new Date(Date.now() + 365 * 24 * 3600 * 1000),
        holderKey: holderPub,
        claims: {
          given_name: 'Erika',
          family_name: 'Mustermann',
          birthdate: '1963-08-12',
        },
        disclose: [['given_name'], ['family_name'], ['birthdate']],
      },
      { signer: new P256Provider(bytesToHex(issuerPriv)), publicKey: issuerPub, kid: 'key-1' },
    );
    const issued = cred.serialize();
    expect(issued.endsWith('~')).toBe(true);
    expect(issued.split('~')[0].split('.').length).toBe(3);
    expect(cred.hash()).toMatch(/^[0-9a-f]{64}$/);

    const held = parse(issued);
    const presentation = await held.present({
      reveal: [['given_name']],
      keyBinding: {
        signer: new P256Provider(bytesToHex(holderPriv)),
        audience: verifier,
        nonce,
        issuedAt: new Date(),
      },
    });
    const sent = presentation.serialize();
    expect(sent.endsWith('~')).toBe(false);

    const received = parse(sent);
    const res = await received.verify(
      new StaticResolver(iss, [{ kid: 'key-1', publicKey: issuerPub }]),
      { audience: verifier, nonce },
    );
    expect(res.issuer).toBe(iss);
    expect(res.vct).toBe('https://credentials.example/identity_credential');
    expect(res.keyBound).toBe(true);
    expect(res.claims.given_name).toBe('Erika');
    expect(res.claims.family_name).toBeUndefined();
  });

  it('rejects a token that is not an SD-JWT', () => {
    expect(() => parse('not-a-jwt')).toThrow(/~/);
  });
});
