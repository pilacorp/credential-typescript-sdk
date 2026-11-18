import * as http from 'node:http';
import { p256 } from '@noble/curves/nist';
import { P256Provider } from '../../src/common/signer/p256-provider';
import { bytesToHex } from '../../src/common/crypto/hex';
import { Checker, decodeList, List } from '../../src/digitalcredential/statuslist';
import { StaticResolver } from '../../src/digitalcredential/issuerkey';
import { issue, parse } from '../../src/digitalcredential';

describe('statuslist (draft-ietf-oauth-status-list-21)', () => {
  it('decodes the draft §4.2 1-bit example', () => {
    const l = decodeList('eNrbuRgAAhcBXQ', 1);
    expect([...l.bytes()]).toEqual([0xb9, 0xa3]);
    const want = [1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1];
    want.forEach((v, i) => expect(l.get(i)).toBe(v));
  });

  it('round-trips Encode through Decode', () => {
    const l = List.fromBytes(Buffer.from([0xb9, 0xa3]), 1);
    const back = decodeList(l.encode(), 1);
    expect([...back.bytes()]).toEqual([0xb9, 0xa3]);
  });

  it('sets entry 917 in a 1-bit list as the draft locates it', () => {
    const l = List.new(1000, 1);
    l.set(917, 1);
    expect(l.bytes()[114]).toBe(0b0010_0000);
    expect(l.get(917)).toBe(1);
  });

  it('issues a token and Checker.Status reads VALID over HTTP', async () => {
    const issuerPriv = p256.utils.randomPrivateKey();
    const issuerPub = p256.getPublicKey(issuerPriv, false);
    const iss = 'https://issuer.example';
    const list = List.new(16, 1);
    const holder: { token?: string } = {};
    const server = http.createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/statuslist+jwt' });
      res.end(holder.token);
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const { port } = server.address() as { port: number };
    const uri = `http://127.0.0.1:${port}/status`;
    holder.token = await list.issueToken(
      { sub: uri, issuedAt: new Date(), ttlSeconds: 60 },
      { signer: new P256Provider(bytesToHex(issuerPriv)), publicKey: issuerPub, kid: 'key-1' },
    );
    const checker = new Checker({
      issuers: new StaticResolver(iss, [{ kid: 'key-1', publicKey: issuerPub }]),
      fetch,
      insecureHTTP: true,
    });
    try {
      expect(await checker.status({ uri, index: 3 }, iss)).toBe(0);

      const cred = await issue(
        {
          issuer: iss,
          vct: 'https://credentials.example/id',
          status: { idx: 3, uri },
          claims: { given_name: 'Erika' },
        },
        { signer: new P256Provider(bytesToHex(issuerPriv)), publicKey: issuerPub, kid: 'key-1' },
      );
      const res = await parse(cred.serialize()).verify(new StaticResolver(iss, [{ kid: 'key-1', publicKey: issuerPub }]), {
        status: checker,
      });
      expect(res.status).toBe(0);
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  });
});
