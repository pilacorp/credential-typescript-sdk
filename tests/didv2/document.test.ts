import { DIDTypePeople, newSecp256k1VM, newSpec } from '../../src/didv2';
import { generateDIDDocument } from '../../src/didv2/document';
import { docHash, parseSubID, subDIDFor, validateSubDID } from '../../src/didv2/subdid';

export const rootR1 = 'did:nda:0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a';
export const rootR2 = 'did:nda:0x681248d5c48008ce14e5aebab76ce15476ad2509';
export const subIDS1 = '0b8e6f3c-5a1d-4c27-9f40-3e2a7d91c6b5';
export const row1PublicKeyHex = '0x03354b9ae48c3cecaf6636ba88e321847edbf450a2777a012240d6d51705de73d7';
export const row1SubDID = 'did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071';
export const row2PublicKeyHex = '0x03eea1acf8f417b7825a00be2bf446ef87da146f58e664f36f85f91e74d4f79dc1';
export const row2SubDID = 'did:nda:0x97c19e066bdaa1bc4788e3c2e6c35c7e7bfc73af';
export const rootConsentR1 =
  '0x45b815352a92764deec8dd6bd5f8842332f3e5548f75f803602ec99086537fb63bfa08f1ed32a03d3d33e7f455d4d78cb00877f4c8689c28f41b69dca8a5fa511c';
export const createSubDIDJSON =
  '{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/v1"],"id":"did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071","controller":"did:nda:0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a","verificationMethod":[{"id":"did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071#key-1","type":"EcdsaSecp256k1VerificationKey2019","controller":"did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071","publicKeyHex":"0x03354b9ae48c3cecaf6636ba88e321847edbf450a2777a012240d6d51705de73d7"}],"authentication":["did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071#key-1"],"assertionMethod":["did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071#key-1"],"didDocumentMetadata":{"rootConsent":"0x45b815352a92764deec8dd6bd5f8842332f3e5548f75f803602ec99086537fb63bfa08f1ed32a03d3d33e7f455d4d78cb00877f4c8689c28f41b69dca8a5fa511c","subId":"0b8e6f3c-5a1d-4c27-9f40-3e2a7d91c6b5","type":"people"}}';
export const createSubDIDDocHash = '0xd40e8cdf47ef809607d4be35edfc75aa9cbc3bda443ab93c706956ecdba3d8a8';
export const registerSubDIDJSON =
  '{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/v1"],"id":"did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071","controller":"did:nda:0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a","verificationMethod":[{"id":"did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071#key-1","type":"EcdsaSecp256k1VerificationKey2019","controller":"did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071","publicKeyHex":"0x03354b9ae48c3cecaf6636ba88e321847edbf450a2777a012240d6d51705de73d7"}],"authentication":["did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071#key-1"],"assertionMethod":["did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071#key-1"],"didDocumentMetadata":{"rootConsent":"0x45b815352a92764deec8dd6bd5f8842332f3e5548f75f803602ec99086537fb63bfa08f1ed32a03d3d33e7f455d4d78cb00877f4c8689c28f41b69dca8a5fa511c","type":"people"}}';
export const registerSubDIDDocHash = '0x0d19356dd2d8688182a95aa166b7eb0b1f5516821f06b147d50c70e3bd743eec';

describe('didv2 subdid document', () => {
  test('SubDIDFor KDF rows', () => {
    expect(subDIDFor(rootR1, row1PublicKeyHex)).toBe(row1SubDID);
    expect(subDIDFor(rootR1, row2PublicKeyHex)).toBe(row2SubDID);
  });

  test('ParseSubID refuses', () => {
    for (const bad of ['NV-0012', `${'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-'}a`, 'NV 00123', 'NV.00123', '']) {
      expect(() => parseSubID(bad)).toThrow();
    }
  });

  test('ValidateSubDID', () => {
    const ok = generateDIDDocument(row1PublicKeyHex, row1SubDID, '', rootR1, DIDTypePeople, { subId: subIDS1 })!;
    expect(() => validateSubDID(ok, rootR1)).not.toThrow();
    const second = generateDIDDocument(row1PublicKeyHex, row1SubDID, '', rootR1, DIDTypePeople, null, [
      newSpec(newSecp256k1VM(row1SubDID, '#key-2', row2PublicKeyHex)),
    ])!;
    expect(() => validateSubDID(second, rootR1)).not.toThrow();
    const wrong = generateDIDDocument(row1PublicKeyHex, row1SubDID, '', rootR1, DIDTypePeople, null)!;
    wrong.controller = rootR2;
    expect(() => validateSubDID(wrong, rootR1)).toThrow();
  });

  test('DocHash vectors', () => {
    expect(docHash(JSON.parse(createSubDIDJSON))).toBe(createSubDIDDocHash);
    expect(docHash(JSON.parse(registerSubDIDJSON))).toBe(registerSubDIDDocHash);
  });
});
