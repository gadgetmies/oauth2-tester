import {
  AccessTokenRequestOptions,
  AccessTokenResponse,
  AccountGeneratorFn,
  AuthorizationCodeDetails,
  AuthorizationCodeRequestOptions,
  Client,
  ClientGeneratorFn,
  ConsentFn,
  LoginFn,
  OAuthProperties,
  RegisterAccountFn,
  RemoveAccountFn,
  RemoveClientFn,
  TestFunctions,
  UserAccount,
} from './types'
import base64url from 'base64url'
import * as uuid from 'uuid'
import * as crypto from 'crypto'
import {
  SharedAuthorizationCodeGrantTester,
  SharedAuthorizationCodeGrantTesterOptions,
} from './SharedAuthorizationCodeGrantTester'
import { TestHelpers } from './testHelpers'

import axios, { AxiosResponse } from 'axios'
import * as toughCookie from 'tough-cookie'
import axiosCookiejarSupport from 'axios-cookiejar-support'

axiosCookiejarSupport(axios)

export class AuthorizationCodeGrantWithPKCETester extends SharedAuthorizationCodeGrantTester {
  private readonly codeChallengeMethod: 'S256' | 'plain'
  private codeVerifierForAuthorizationCode: { [k: string]: string } = {}

  constructor(
    oauthProperties: OAuthProperties,
    client: {
      clientGenerator: ClientGeneratorFn
      removeClient: RemoveClientFn
    },
    user: {
      registerAccount: RegisterAccountFn
      removeAccount: RemoveAccountFn
      login: LoginFn
      consent: ConsentFn
      accountGenerator: AccountGeneratorFn
    },
    options: SharedAuthorizationCodeGrantTesterOptions,
    pkce: {
      codeChallengeMethod: 'S256' | 'plain'
    } = {
      codeChallengeMethod: 'plain',
    }
  ) {
    super(oauthProperties, client, user, options)
    this.codeChallengeMethod = pkce.codeChallengeMethod
  }

  register(testFunctions) {
    describe('Authorization Code Grant with PKCE', () => {
      super.registerSharedTests(testFunctions)
      const helpers = new TestHelpers(testFunctions.fail)

      this.registerFailingAuthorizationCodeTests(testFunctions, helpers)
      this.registerFailingAccessTokenTests(testFunctions, helpers)
    })
  }

  registerFailingAuthorizationCodeTests(
    { describe, it, before, after, fail }: TestFunctions,
    { expectRedirectToIncludeQuery }: TestHelpers
  ) {
    describe('when requesting authorization code', () => {
      let user: UserAccount
      const redirectUri = 'https://an-awesome-service.com/'
      const clientName = uuid.v4()
      let client

      before('Generate OAuth client', async () => {
        client = await this.clientGenerator(clientName, redirectUri, this.oauthProperties.availableScopes())
      })

      const registerSetupAndTearDown = () => {
        before('Register user', async () => {
          user = await this.accountGenerator()
          await this.registerAccount(user)
          this.cookieJars[user.username] = new toughCookie.CookieJar()
        })

        after('Remove user', async () => {
          await this.removeAccount(user.username)
        })
      }

      describe('with invalid code challenge method', () => {
        registerSetupAndTearDown()
        it('should fail', async () => {
          await expectRedirectToIncludeQuery(redirectUri, { error: 'invalid_request' }, () =>
            this.requestAuthorizationCode(client, user, {
              scopes: this.oauthProperties.availableScopes(),
              extraParams: {
                codeChallengeMethod: 'invalid-method',
              },
            })
          )
        })
      })

      describe('with missing code challenge method', () => {
        registerSetupAndTearDown()

        it('should fail', async () => {
          await expectRedirectToIncludeQuery(redirectUri, { error: 'invalid_request' }, () =>
            this.requestAuthorizationCode(client, user, {
              scopes: this.oauthProperties.availableScopes(),
              extraParams: {
                codeChallengeMethod: undefined,
              },
            })
          )
        })
      })
    })
  }

  registerFailingAccessTokenTests(
    { describe, it, before, after, fail }: TestFunctions,
    { expectToFailWithStatus, expextToFailWithStatusAndDataIncluding }: TestHelpers
  ) {
    describe('when fetching access token', () => {
      let authorizationCodeDetails: AuthorizationCodeDetails
      let user: UserAccount
      const redirectUri = 'https://an-awesome-service.com/'
      const codeVerifier = uuid.v4()
      const clientName = uuid.v4()
      let client

      const registerSetupAndTearDown = () => {
        before('Register user', async () => {
          user = await this.accountGenerator()
          await this.registerAccount(user)
          this.cookieJars[user.username] = new toughCookie.CookieJar()
        })

        before('fetch authorization code', async () => {
          authorizationCodeDetails = await this.fetchAuthorizationCode(client, user, {
            scopes: this.oauthProperties.availableScopes(),
            extraParams: {
              codeVerifier,
            },
          })
        })

        after('Remove user', async () => {
          await this.removeAccount(user.username)
        })
      }

      before('Generate OAuth client', async () => {
        client = await this.clientGenerator(clientName, redirectUri, this.oauthProperties.availableScopes())
      })

      describe('with missing client details', () => {
        describe('with missing client_id', () => {
          registerSetupAndTearDown()
          it('access token request should fail', async () => {
            await expextToFailWithStatusAndDataIncluding(400, { error: 'invalid_request' }, () =>
              this.fetchAccessToken(client, authorizationCodeDetails, {
                user,
                extraParams: { client_id: undefined },
              })
            )
          })
        })

        describe('with incorrect client id', () => {
          registerSetupAndTearDown()

          it('access token request should fail', () =>
            expextToFailWithStatusAndDataIncluding(401, { error: 'invalid_client' }, () =>
              this.fetchAccessToken({ ...client, clientId: 'invalid-client-id' }, authorizationCodeDetails, { user })
            ))
        })
      })

      describe('with incorrect client details', () => {
        describe('with incorrect client id', () => {
          registerSetupAndTearDown()

          it('should fail', () =>
            expectToFailWithStatus(401, () =>
              this.fetchAccessTokenWithCodeVerifier(
                { ...client, clientId: 'invalid-client-id' },
                authorizationCodeDetails,
                codeVerifier,
                { user }
              )
            ))
        })

        describe('with incorrect redirect URI port', () => {
          registerSetupAndTearDown()

          it('should fail', () =>
            expectToFailWithStatus(401, () =>
              this.fetchAccessTokenWithCodeVerifier(
                { ...client, redirectUri: 'http://localhost:5001' },
                authorizationCodeDetails,
                codeVerifier,
                { user }
              )
            ))
        })

        describe('with incorrect redirect URI', () => {
          registerSetupAndTearDown()

          it('should fail', () =>
            expectToFailWithStatus(401, () =>
              this.fetchAccessTokenWithCodeVerifier(
                {
                  ...client,
                  redirectUri: 'http://some-incorrect-uri.com',
                },
                authorizationCodeDetails,
                codeVerifier,
                { user }
              )
            ))
        })
      })

      describe('with incorrect request details', () => {
        describe('with incorrect code verifier', () => {
          registerSetupAndTearDown()
          it('should fail', async () => {
            await expextToFailWithStatusAndDataIncluding(400, { error: 'invalid_grant' }, () =>
              this.fetchAccessTokenWithCodeVerifier(client, authorizationCodeDetails, 'invalid-code-verifier', { user })
            )
          })
        })
      })
    })
  }

  async requestAuthorizationCode(
    client: Client,
    user: UserAccount,
    options: AuthorizationCodeRequestOptions = {}
  ): Promise<AxiosResponse> {
    const extraParams = options.extraParams || {}
    const codeVerifier = extraParams.hasOwnProperty('codeVerifier') ? extraParams.codeVerifier : uuid.v4()
    delete extraParams.codeVerifier
    const codeChallengeMethod = extraParams.hasOwnProperty('codeChallengeMethod')
      ? extraParams.codeChallengeMethod
      : this.codeChallengeMethod
    delete extraParams.codeChallengeMethod
    const authorizationCodeResponse = await super.requestAuthorizationCode(client, user, {
      ...options,
      shouldConsent: options.shouldConsent === undefined ? true : options.shouldConsent,
      extraParams: {
        ...extraParams,
        code_challenge: this.generateCodeChallenge(codeVerifier),
        code_challenge_method: codeChallengeMethod,
      },
    })

    this.storeVerifierFromResponse(authorizationCodeResponse, codeVerifier)

    return authorizationCodeResponse
  }

  generateCodeChallenge(codeVerifier: string): string {
    if (this.codeChallengeMethod === 'plain') {
      return codeVerifier
    }
    return base64url.encode(crypto.createHash('sha256').update(codeVerifier).digest())
  }

  getCodeVerifier(authorizationCode: string): string {
    return this.codeVerifierForAuthorizationCode[authorizationCode]
  }

  async fetchAccessToken(
    client: Client,
    authorizationCodeDetails: AuthorizationCodeDetails,
    options: AccessTokenRequestOptions
  ): Promise<AccessTokenResponse> {
    const codeVerifier = this.getCodeVerifier(authorizationCodeDetails.authorizationCode)
    return this.fetchAccessTokenWithCodeVerifier(client, authorizationCodeDetails, codeVerifier, options)
  }

  async fetchAccessTokenWithCodeVerifier(
    client: Client,
    authorizationCodeDetails: AuthorizationCodeDetails,
    codeVerifier: string,
    options: AccessTokenRequestOptions
  ): Promise<AccessTokenResponse> {
    const data = SharedAuthorizationCodeGrantTester.generateQueryString({
      grant_type: 'authorization_code',
      code: authorizationCodeDetails.authorizationCode,
      redirect_uri: client.redirectUri,
      client_id: client.clientId,
      code_verifier: codeVerifier,
      ...options.extraParams,
    })

    this.debugLog('Requesting access token with data', data)

    const jar = this.cookieJars[options.user.username]

    const res = await axios({
      data,
      jar,
      method: 'POST',
      url: this.oauthProperties.tokenEndpoint(),
      maxRedirects: 0,
    })
    this.responseLog('Access token response:', res.data)

    if (res.status === 302) {
      throw new Error('Server redirected an access token request!')
    }

    if (res.headers.hasOwnProperty('set-cookie')) {
      throw new Error('Access token response should not contain a set-cookie header!')
    }

    const scopes = res.data.scope !== undefined ? res.data.scope.split(' ') : undefined

    return {
      accessTokenDetails: {
        scopes,
        accessToken: res.data.access_token,
        expiresIn: res.data.expires_in,
        tokenType: res.data.token_type,
      },
    }
  }

  storeVerifierFromResponse(res: AxiosResponse, codeVerifier: string) {
    const error = new URL(res.headers.location).searchParams.get('error')

    if (!error) {
      this.codeVerifierForAuthorizationCode[this.extractAuthorizationCodeFromResponse(res)] = codeVerifier
    }
  }
}
