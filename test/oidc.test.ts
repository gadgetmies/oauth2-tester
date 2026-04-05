import { OIDCTester, OIDCProperties, TestFunctions, AuthorizationCodeGrantWithoutPKCETester } from '../src'

describe('OIDCTester verification', () => {
  it('should instantiate OIDCTester and register suites', () => {
    const oidcProps: OIDCProperties = {
      authorizationEndpoint: () => 'http://localhost/authorize',
      tokenEndpoint: () => 'http://localhost/token',
      availableScopes: () => ['openid'],
      issuer: () => 'http://localhost',
      discoveryEndpoint: () => 'http://localhost/.well-known/openid-configuration',
      userinfoEndpoint: () => 'http://localhost/userinfo'
    }

    const mockOAuthTester = {} as any
    const oidcTester = new OIDCTester(oidcProps, mockOAuthTester)

    const testFunctions: TestFunctions = {
      it: jest.fn(),
      step: jest.fn(),
      describe: jest.fn(),
      before: jest.fn(),
      after: jest.fn(),
      fail: jest.fn()
    }

    oidcTester.registerDiscoveryTests(testFunctions)
    oidcTester.registerIDTokenTests(testFunctions)
    oidcTester.registerUserInfoTests(testFunctions)

    expect(testFunctions.describe).toHaveBeenCalledWith('OIDC Discovery', expect.any(Function))
    expect(testFunctions.describe).toHaveBeenCalledWith('OIDC ID Token', expect.any(Function))
    expect(testFunctions.describe).toHaveBeenCalledWith('OIDC UserInfo', expect.any(Function))
  })
})
