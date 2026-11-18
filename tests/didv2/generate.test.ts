import { DIDTypePeople } from '../../src/didv2';
import { DefaultProvider } from '../../src/didv2/signer';
import { generateSubDID } from '../../src/didv2/subdid';
import { createSubDIDJSON, row1PublicKeyHex, row1SubDID, rootR1, subIDS1 } from './document.test';

const createSignature =
  '0x73ffc216c50a9cbdf28d8eac72954f337974e390e83427abe79d3ed5bea8ee7e602b23159cf8ce401bf7e5fc2de553568e9c3a9359267fc393e5033f7fa59ce61b';
const row1PrivateKeyHex = '46c9a6cf35b07f7d3f5d37f75bf671cc1251d9399a2db28e35b0942765cde8e8';
const rootR1PrivateKeyHex = '1111111111111111111111111111111111111111111111111111111111111111';

describe('didv2 GenerateSubDID', () => {
  test('document and signature vectors', async () => {
    const res = await generateSubDID(
      rootR1,
      subIDS1,
      row1PublicKeyHex,
      DIDTypePeople,
      null,
      new DefaultProvider(rootR1PrivateKeyHex),
      new DefaultProvider(row1PrivateKeyHex),
    );
    expect(JSON.stringify(res.document)).toBe(createSubDIDJSON);
    expect(res.signature).toBe(createSignature);
    expect(res.did).toBe(row1SubDID);
    expect(res.type).toBe('people');
  });

  test('refuses mismatched signers', async () => {
    await expect(
      generateSubDID(
        rootR1,
        subIDS1,
        row1PublicKeyHex,
        DIDTypePeople,
        null,
        new DefaultProvider(row1PrivateKeyHex),
        new DefaultProvider(row1PrivateKeyHex),
      ),
    ).rejects.toThrow();
    await expect(
      generateSubDID(
        rootR1,
        subIDS1,
        row1PublicKeyHex,
        DIDTypePeople,
        null,
        new DefaultProvider(rootR1PrivateKeyHex),
        new DefaultProvider(rootR1PrivateKeyHex),
      ),
    ).rejects.toThrow();
  });
});
