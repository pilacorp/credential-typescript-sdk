import { merkleProof, merkleRoot, revokedLeaf, verifyProof } from '../../src/didv2/subdid/merkle';

function fixtureLeaves(n: number): string[] {
  return Array.from({ length: n }, (_, i) => `0x${Buffer.alloc(32, i + 1).toString('hex')}`);
}

describe('didv2 subdid merkle', () => {
  test('root vectors', () => {
    const vectors: Array<[number, string]> = [
      [1, '0x0101010101010101010101010101010101010101010101010101010101010101'],
      [2, '0x346d8c96a2454213fcc0daff3c96ad0398148181b9fa6488f7ae2c0af5b20aa0'],
      [3, '0x1d614fa3c8de62938b0948972494f9a3858575db69ce1d34c77926f30732c981'],
      [5, '0x55d458ff264cc10cb4ef71d27a18db86f587999b2355cfa5eb5fccf8c973bced'],
    ];
    for (const [n, root] of vectors) {
      expect(merkleRoot(fixtureLeaves(n))).toBe(root);
    }
  });

  test('proof vectors', () => {
    expect(merkleProof(fixtureLeaves(5), 4)).toEqual([
      '0x0b242b9a6559f2d9f8563485a0697b746ec58ce879e0e5ac94d4c8a250723121',
    ]);
    expect(merkleProof(fixtureLeaves(5), 2)).toEqual([
      '0x0404040404040404040404040404040404040404040404040404040404040404',
      '0x346d8c96a2454213fcc0daff3c96ad0398148181b9fa6488f7ae2c0af5b20aa0',
      '0x0505050505050505050505050505050505050505050505050505050505050505',
    ]);
    const leaves = fixtureLeaves(5);
    const proof = merkleProof(leaves, 2);
    expect(verifyProof(leaves[2], proof, merkleRoot(leaves))).toBe(true);
  });

  test('revoked leaf vectors', () => {
    expect(revokedLeaf('0x86b2efd244acb31eb238a65ca05476ab42558071')).toBe(
      '0x83c91d2020210e4924defde940dcb4e63ec3f20bbad4229da6019faba05cc206',
    );
    expect(revokedLeaf('0x5b6a5525e2c2d2428554b04d24b3bb5c1f3f5ae3')).toBe(
      '0xa0fed93a6a92b69bcbc4e8f5983d5ede26eef742274c3700b5e400a4c8856c3d',
    );
    const leaves = fixtureLeaves(3);
    leaves[2] = revokedLeaf('0x86b2efd244acb31eb238a65ca05476ab42558071');
    expect(merkleRoot(leaves)).toBe('0x934b02ce8ddedb479ffc1fad0eaf40f0cd0d75e853f9d28e9b1273fd49004993');
  });
});
