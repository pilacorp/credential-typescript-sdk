import * as sdk from '../src/index';

describe('public exports', () => {
  it('exposes JOSE, P-256, dual-curve, errors, and ecdsasd', () => {
    expect(sdk.JOSECredential).toBeDefined();
    expect(sdk.TypeVCJWT).toBe('vc+jwt');
    expect(sdk.TypeVCSDJWT).toBe('vc+sd-jwt');
    expect(sdk.P256Provider).toBeDefined();
    expect(sdk.generateDualCurveKeyPair).toBeDefined();
    expect(sdk.generateP256KeyPair).toBeDefined();
    expect(sdk.validateDidDocument).toBeDefined();
    expect(sdk.CredentialError).toBeDefined();
    expect(sdk.ErrorCode.AudienceUnbound).toBe('audience_unbound');
    expect(sdk.ecdsasd.Cryptosuite).toBe('ecdsa-sd-2023');
    expect(sdk.ECDSASDCredential).toBeDefined();
    expect(sdk.did).toBeDefined();
    expect(sdk.verificationMethod.encodeP256PublicMultibase).toBeDefined();
    expect(sdk.credentialStatus.StatusListClient).toBeDefined();
    expect(sdk.credentialStatus.bitAt).toBeDefined();
    expect(sdk.StatusListClient).toBeDefined();
    expect(sdk.bitAt).toBeDefined();
    expect(sdk.addVerificationMethod).toBeDefined();
    expect(sdk.rotateVerificationMethod).toBeDefined();
    expect(sdk.revokeVerificationMethod).toBeDefined();
    expect(sdk.bundledContextUrls().length).toBeGreaterThan(5);
    expect(sdk.registerContext).toBeDefined();
    expect(sdk.withDocumentLoader).toBeDefined();
  });
});
