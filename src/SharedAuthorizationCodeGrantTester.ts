import {
  AccessTokenDetails,
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
  ResourceRequestTestFn,
  TestFunctions,
  UserAccount,
} from './types'
import OAuth2Tester from './OAuth2Tester'
import { TestHelpers } from './testHelpers'
import * as uuid from 'uuid'
import axios, { AxiosPromise, AxiosRequestConfig, AxiosResponse } from 'axios'
import * as toughCookie from 'tough-cookie'
import axiosCookiejarSupport from 'axios-cookiejar-support'
import * as R from 'ramda'
import debug from 'debug'

const debugLog = debug('oauth2-tester')

axiosCookiejarSupport(axios)

export type SharedAuthorizationCodeGrantTesterOptions = { useRefreshTokens: boolean }

const requestWithAccessToken = (accessToken: AccessTokenDetails) => (
  config: AxiosRequestConfig,
  overrideAccessToken?: string
): AxiosPromise => {
  if (config.validateStatus && overrideAccessToken) {
    throw new Error(
      'You should not define both the config.validateStatus and overrideAccessToken. ' +
        'The server is expected to always return 401 for invalid access tokens.'
    )
  }

  const c = {
    ...config,
    validateStatus: overrideAccessToken ? (status) => status === 401 : config.validateStatus,
    headers: { ...config.headers, Authorization: `Bearer ${overrideAccessToken || accessToken.accessToken}` },
  }

  debugLog('Request with access token', c)
  return axios(c)
}

export abstract class SharedAuthorizationCodeGrantTester extends OAuth2Tester {
  // Needed for authorization code and resource owner password grants
  protected registerAccount: RegisterAccountFn
  protected accountGenerator: AccountGeneratorFn

  // Needed for authorization code grant
  protected login: LoginFn
  protected consent: ConsentFn
  protected removeAccount: RemoveAccountFn
  protected cookieJars: { [x: string]: toughCookie.CookieJar } = {}
  private options: SharedAuthorizationCodeGrantTesterOptions

  protected constructor(
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
    options: SharedAuthorizationCodeGrantTesterOptions
  ) {
    super(oauthProperties, client)
    this.registerAccount = user.registerAccount
    this.removeAccount = user.removeAccount
    this.login = user.login
    this.consent = user.consent
    this.accountGenerator = user.accountGenerator
    this.options = options
  }

  logout(user: UserAccount) {
    delete this.cookieJars[user.username]
  }

  async removeUser(user: UserAccount) {
    this.logout(user)
    await this.removeAccount(user.username)
  }

  registerResourceRequestTests(scopes: string[], testFunctions: TestFunctions, tests: ResourceRequestTestFn[]) {
    const { step, before, after } = testFunctions
    const redirectUri: string = 'https://an-awesome-service.com/'
    const clientName: string = uuid.v4()
    let client: Client
    let user: UserAccount
    let authorizationCodeDetails: AuthorizationCodeDetails
    let accessTokenDetails: AccessTokenDetails

    before('Generate OAuth client', async () => {
      client = await this.clientGenerator(clientName, redirectUri, scopes)
    })

    before('Generate user details', async () => {
      user = await this.accountGenerator()
    })

    before('Register user', async () => {
      await this.registerAccount(user)
      this.cookieJars[user.username] = new toughCookie.CookieJar()
    })

    after('Remove OAuth client', async () => {
      await this.removeAccount(user.username)
      await this.removeClient(clientName)
    })

    step('Fetch authorization code for all scopes', async () => {
      authorizationCodeDetails = await this.fetchAuthorizationCode(client, user, {
        scopes,
      })
    })

    step('Fetch access token', async () => {
      const accessTokenResponse = await this.fetchAccessToken(client, authorizationCodeDetails)
      accessTokenDetails = accessTokenResponse.accessTokenDetails
    })

    step('Resource requests', async () => {
      for (const test of tests) {
        await test(requestWithAccessToken(accessTokenDetails))
      }
    })
  }

  registerSharedTests(testFunctions: TestFunctions) {
    const { describe, it, step, before, after, fail } = testFunctions
    const {
      expextToFailWithStatusAndDataIncluding,
      expectRedirectToIncludeQuery,
      expectToFailWithStatus,
    } = new TestHelpers(fail)

    const redirectUri = 'https://an-awesome-service.com/' // TODO: specify in suites

    describe('shared authorization code grant tests', () => {
      describe('when request details are valid', () => {
        const clientName = uuid.v4()
        let client
        const availableScopes = this.oauthProperties.availableScopes()

        before('Generate OAuth client', async () => {
          client = await this.clientGenerator(clientName, redirectUri, availableScopes)
        })

        after('Remove OAuth client', async () => {
          await this.removeClient(clientName)
        })

        const verifyScopes = (expected: string[], actual: string[]) => {
          if (R.without(expected, actual).length !== 0) {
            fail(expected, actual, `Returned scopes do not match requested. Actual: ${actual}, expected: ${expected}`)
          }
        }

        describe('when using all scopes', () => {
          let user: UserAccount
          let authorizationCodeDetails: AuthorizationCodeDetails
          let accessTokenResponse: AccessTokenResponse

          before('Generate user details', async () => {
            user = await this.accountGenerator()
          })

          before('Register user', async () => {
            await this.registerAccount(user)
            this.cookieJars[user.username] = new toughCookie.CookieJar()
          })

          after('Remove user', () => this.removeUser(user))

          step('Fetch authorization code for all scopes', async () => {
            authorizationCodeDetails = await this.fetchAuthorizationCode(client, user, {
              scopes: availableScopes,
            })

            if (!authorizationCodeDetails.authorizationCode) {
              fail('Authorization code was not returned or was empty')
            }

            verifyScopes(authorizationCodeDetails.scopes, availableScopes)
          })

          step('Fetch access token', async () => {
            accessTokenResponse = await this.fetchAccessToken(client, authorizationCodeDetails)

            const accessTokenDetails = accessTokenResponse.accessTokenDetails
            if (!accessTokenDetails.accessToken) {
              fail('Access token was not returned or was empty')
            }

            if (
              this.options.useRefreshTokens &&
              (!accessTokenResponse.refreshTokenDetails || !accessTokenResponse.refreshTokenDetails.refreshToken)
            ) {
              fail('Refresh token was not returned or was empty')
            }

            verifyScopes(accessTokenDetails.scopes, availableScopes)
          })
        })

        describe('when using single scope', () => {
          for (const scope of this.oauthProperties.availableScopes()) {
            let authorizationCodeDetails: AuthorizationCodeDetails
            let accessTokenResponse: AccessTokenResponse

            describe(`with scope: ${scope}`, () => {
              let user

              before('Generate user details', async () => {
                user = await this.accountGenerator()
              })

              before('Register user', async () => {
                await this.registerAccount(user)
                this.cookieJars[user.username] = new toughCookie.CookieJar()
              })

              after('Remove user', () => this.removeUser(user))

              step(`Fetch authorization code`, async () => {
                authorizationCodeDetails = await this.fetchAuthorizationCode(client, user, {
                  scopes: [scope],
                })

                if (!authorizationCodeDetails.authorizationCode) {
                  fail('Authorization code was not returned or was empty')
                }

                verifyScopes(authorizationCodeDetails.scopes, [scope])
              })

              step('Fetch access token', async () => {
                accessTokenResponse = await this.fetchAccessToken(client, authorizationCodeDetails)

                const accessTokenDetails = accessTokenResponse.accessTokenDetails
                if (!accessTokenDetails.accessToken) {
                  fail('Access token was not returned or was empty')
                }

                verifyScopes(accessTokenDetails.scopes, [scope])
              })
            })
          }
        })
      })

      describe('when reusing the authorization code', () => {
        const clientName = uuid.v4()
        let client: Client
        let user: UserAccount
        let authorizationCodeDetails: AuthorizationCodeDetails
        let accessTokenResponse: AccessTokenResponse

        before('Generate OAuth client', async () => {
          client = await this.clientGenerator(clientName, redirectUri, this.oauthProperties.availableScopes())
        })

        before('Register user', async () => {
          user = await this.accountGenerator()
          await this.registerAccount(user)
          this.cookieJars[user.username] = new toughCookie.CookieJar()
        })

        before('Fetch authorization code', async () => {
          authorizationCodeDetails = await this.fetchAuthorizationCode(client, user, {
            scopes: this.oauthProperties.availableScopes(),
          })
        })

        before('Fetch access token', async () => {
          accessTokenResponse = await this.fetchAccessToken(client, authorizationCodeDetails)
        })

        after('Remove user', () => this.removeUser(user))

        after('Remove OAuth client', async () => {
          await this.removeClient(clientName)
        })

        it('fails if authorization code is reused', () => {
          return expextToFailWithStatusAndDataIncluding(400, { error: 'invalid_grant' }, () =>
            this.fetchAccessToken(client, authorizationCodeDetails)
          )
        })
      })

      describe('when request details are invalid', () => {
        const clientName = uuid.v4()
        let user: UserAccount
        let client: Client
        const availableScopes = this.oauthProperties.availableScopes()

        before('Generate OAuth client', async () => {
          client = await this.clientGenerator(clientName, redirectUri, availableScopes)
        })

        after('Remove OAuth client', async () => {
          await this.removeClient(clientName)
        })

        before('Register user', async () => {
          user = await this.accountGenerator()
          await this.registerAccount(user)
        })

        after('Remove user', () => this.removeUser(user))

        describe('when fetching authorization code', () => {
          beforeEach(() => {
            this.cookieJars[user.username] = new toughCookie.CookieJar()
          })

          it('fails if client_id is not provided', async () => {
            await expextToFailWithStatusAndDataIncluding(400, { error: 'invalid_request' }, () =>
              this.requestAuthorizationCode({ ...client, clientId: undefined }, user, {
                scopes: availableScopes,
              })
            )
          })

          it('fails if scope is invalid', async () => {
            await expectRedirectToIncludeQuery(redirectUri, { error: 'invalid_scope' }, () =>
              this.requestAuthorizationCode(client, user, {
                scopes: ['invalid-scope'],
              })
            )
          })
        })

        describe('when user credentials are invalid', () => {
          it('should fail', async () => {
            try {
              await this.requestAuthorizationCode(
                client,
                {
                  username: 'foo',
                  password: 'bar',
                },
                { scopes: availableScopes }
              )
              fail('Expected to fail with incorrect credentials')
              // tslint:disable-next-line:no-empty
            } catch (e) {}
          })
        })
      })

      describe('when fetching authorization code', () => {
        let user
        const clientName = uuid.v4()
        let client

        before('Generate OAuth client', async () => {
          client = await this.clientGenerator(clientName, redirectUri, this.oauthProperties.availableScopes())
        })

        const registerUserSetupAndTeardown = () => {
          before('Register user', async () => {
            user = await this.accountGenerator()
            await this.registerAccount(user)
            this.cookieJars[user.username] = new toughCookie.CookieJar()
          })

          after('Remove user', () => this.removeUser(user))
        }

        describe('when redirect URI port is incorrect', () => {
          registerUserSetupAndTeardown()
          it('should fail', () => {
            return expectToFailWithStatus(400, () =>
              this.requestAuthorizationCode({ ...client, redirectUri: `${redirectUri}:5000` }, user, {
                scopes: this.oauthProperties.availableScopes(),
              })
            )
          })
        })

        describe('when redirect URI is incorrect', () => {
          registerUserSetupAndTeardown()
          it('should fail', () => {
            return expectToFailWithStatus(400, () =>
              this.requestAuthorizationCode({ ...client, redirectUri: 'http://some-incorrect-uri.com' }, user, {
                scopes: this.oauthProperties.availableScopes(),
              })
            )
          })
        })

        describe('when user does not consent', () => {
          registerUserSetupAndTeardown()
          it('should fail', async () => {
            await expectRedirectToIncludeQuery(redirectUri, { error: 'access_denied' }, () =>
              this.requestAuthorizationCode(client, user, {
                shouldConsent: false,
                scopes: this.oauthProperties.availableScopes(),
              })
            )
          })
        })
      })
    })
  }

  private static getRedirectQueryError(response: AxiosResponse) {
    const location = response.headers.location
    if (!location) {
      return null
    }
    const query = location.substring(location.indexOf('?'))
    if (!query) {
      return null
    }

    return new URLSearchParams(query).get('error')
  }

  async requestAuthorizationCode(
    client: Client,
    user: UserAccount,
    options: AuthorizationCodeRequestOptions = {
      extraParams: {},
    }
  ): Promise<AxiosResponse> {
    options.shouldConsent = options.shouldConsent === undefined ? true : options.shouldConsent
    const jar = this.cookieJars[user.username]

    const params = {
      client_id: client.clientId,
      redirect_uri: client.redirectUri,
      scope: options.scopes ? options.scopes.join(' ') : undefined,
      response_type: 'code',
      ...options.extraParams,
    }

    // tslint:disable-next-line:no-console
    this.debugLog(`Requesting authorization code with params:\n ${JSON.stringify(params, null, 2)}`)

    let authorizationResponse
    try {
      authorizationResponse = await axios({
        jar,
        params,
        url: this.oauthProperties.authorizationEndpoint(),
        method: 'GET',
        withCredentials: true,
      })
    } catch (e) {
      if (e.response) {
        this.responseLog('Authorization request failed with:', e.response.data)
      }
      throw e
    }

    if (SharedAuthorizationCodeGrantTester.getRedirectQueryError(authorizationResponse)) {
      return authorizationResponse
    }

    const loginResponse = await this.login(authorizationResponse, user, jar)
    this.responseLog('Login response:', loginResponse.data)

    if (SharedAuthorizationCodeGrantTester.getRedirectQueryError(loginResponse)) {
      return loginResponse
    }

    const loginRedirectResponse = await this.followRedirect(loginResponse, jar)
    this.responseLog('Login redirect response:', loginRedirectResponse.data)

    if (SharedAuthorizationCodeGrantTester.getRedirectQueryError(loginRedirectResponse)) {
      return loginRedirectResponse
    }

    const consentPageResponse = await this.followRedirect(loginRedirectResponse, jar)
    const consentResponse = await this.consent(options.shouldConsent, consentPageResponse, user, jar, options.scopes)
    this.responseLog('Consent response:', consentResponse.data)

    this.logout(user)
    return consentResponse
  }

  async followRedirect(res: AxiosResponse, jar: toughCookie.CookieJar): Promise<AxiosResponse> {
    const redirectUrl = new URL(res.headers.location, new URL(res.config.url).origin)
    return axios({
      jar,
      url: redirectUrl.toString(),
      method: 'GET',
      withCredentials: true,
      maxRedirects: 0,
      validateStatus: (status) => [200, 302].includes(status),
    })
  }

  extractAuthorizationCodeFromResponse(res: AxiosResponse): string {
    const returnedRedirectUrl = res.headers.location
    const authorizationCode = new URL(returnedRedirectUrl).searchParams.get('code')

    if (!authorizationCode) {
      throw new Error(`Authorization code not returned in redirect url: ${res.headers.location}`)
    }

    return authorizationCode
  }

  async fetchAuthorizationCode(
    client: Client,
    user: UserAccount,
    options: AuthorizationCodeRequestOptions = {
      shouldConsent: true,
      extraParams: {},
    }
  ): Promise<AuthorizationCodeDetails> {
    const res = await this.requestAuthorizationCode(client, user, options)
    const authorizationCode = this.extractAuthorizationCodeFromResponse(res)

    return {
      authorizationCode,
      scopes: options.scopes,
    }
  }

  abstract fetchAccessToken(
    client: Client,
    authorizationCodeDetails: AuthorizationCodeDetails,
    options?: AccessTokenRequestOptions
  ): Promise<AccessTokenResponse>

  async cleanup() {
    return
  }
}
