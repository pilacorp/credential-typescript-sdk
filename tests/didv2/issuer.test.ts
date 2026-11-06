import { recoverAddress, keccak256, hexlify } from 'ethers';
import { DIDTypePeople } from '../../src/didv2';
import { DefaultProvider } from '../../src/didv2/signer';
import { buildIssueDIDPayload, generateCapID, generateIssueDIDSignature } from '../../src/didv2/issuer';
import { DefaultDIDSMCAddress } from '../../src/didv2/config';

describe('didv2 issuer capabilities', () => {
  test('CapID is 32 bytes', () => {
    const id = generateCapID();
    expect(id).toMatch(/^0x[0-9a-f]{64}$/);
  });

  test('EIP-191 payload recovers the issuer', async () => {
    const issuer = new DefaultProvider('11'.repeat(32));
    const capId = `0x${'ab'.repeat(32)}`;
    const payload = {
      contractAddress: DefaultDIDSMCAddress,
      issuerAddress: issuer.getAddress(),
      didAddress: '0x86b2efd244acb31eb238a65ca05476ab42558071',
      didType: DIDTypePeople,
      epoch: 7n,
      capId,
    };
    const packed = buildIssueDIDPayload(payload);
    const sig = await generateIssueDIDSignature(payload, issuer);
    const compact = Buffer.concat([
      Buffer.from(sig.r.toString(16).padStart(64, '0'), 'hex'),
      Buffer.from(sig.s.toString(16).padStart(64, '0'), 'hex'),
      Buffer.from([Number(sig.v)]),
    ]);
    const recovered = recoverAddress(keccak256(packed), hexlify(compact));
    expect(recovered.toLowerCase()).toBe(issuer.getAddress());
  });
});
