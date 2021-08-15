import {
  SharedAuthorizationCodeGrantTester,
  SharedAuthorizationCodeGrantTesterOptions,
} from './SharedAuthorizationCodeGrantTester'
import {
  AccessTokenResponse,
  AccountGeneratorFn,
  AuthorizationCodeDetails,
  Client,
  ClientGeneratorFn,
  ConsentFn,
  LoginFn,
  OAuthProperties,
  RefreshTokenDetails,
  RegisterAccountFn,
  RemoveAccountFn,
  RemoveClientFn,
  UserAccount,
} from './types'
import * as uuid from 'uuid'
import { TestHelpers } from './testHelpers'

import axios from 'axios'
import * as toughCookie from 'tough-cookie'
import axiosCookiejarSupport from 'axios-cookiejar-support'
import * as querystring from 'querystring'
import * as R from 'ramda'

axiosCookiejarSupport(axios)

export class AuthorizationCodeGrantWithoutPKCETester extends SharedAuthorizationCodeGrantTester {
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
    options: SharedAuthorizationCodeGrantTesterOptions
  ) {
    super(oauthProperties, client, user, options)
  }

  register(testFunctions) {
    describe('Authorization Code Grant without PKCE', () => {
      super.registerSharedTests(testFunctions)

      const helpers = new TestHelpers(testFunctions.fail)
      const { expectToBeUnauthorized, expextToFailWithStatusAndDataIncluding } = helpers
      const { before, after, describe, it, fail } = testFunctions

      let authorizationCodeDetails: AuthorizationCodeDetails
      let user: UserAccount
      const redirectUri = 'https://an-awesome-service.com/'
      const expectedAuthenticateDetails = { authenticationType: 'Basic', realm: /.*/ }
      const clientName = uuid.v4()
      let client
      const availableScopes = this.oauthProperties.availableScopes()

      const registerSetupAndTearDown = (scopes: string[] = availableScopes) => {
        before('Register user', async () => {
          user = await this.accountGenerator()
          await this.registerAccount(user)
          this.cookieJars[user.username] = new toughCookie.CookieJar()
        })

        before('fetch authorization code', async () => {
          authorizationCodeDetails = await this.fetchAuthorizationCode(client, user, {
            scopes,
          })
        })

        after('Remove user', async () => {
          await this.removeAccount(user.username)
        })
      }

      before('Generate OAuth client', async () => {
        client = await this.clientGenerator(clientName, redirectUri, availableScopes)
      })

      describe('when fetching access token', () => {
        describe('with incorrect client details', () => {
          describe('with incorrect client id', () => {
            registerSetupAndTearDown()

            it('should fail', () =>
              expectToBeUnauthorized(expectedAuthenticateDetails, () =>
                this.fetchAccessToken({ ...client, clientId: 'invalid-client-id' }, authorizationCodeDetails)
              ))
          })

          describe('with incorrect redirect URI port', () => {
            registerSetupAndTearDown()

            it('should fail', () =>
              expectToBeUnauthorized(expectedAuthenticateDetails, () =>
                this.fetchAccessToken(
                  {
                    ...client,
                    redirectUri: 'http://localhost:5001',
                  },
                  authorizationCodeDetails
                )
              ))
          })

          describe('with incorrect redirect URI', () => {
            registerSetupAndTearDown()

            it('should fail', () =>
              expectToBeUnauthorized(expectedAuthenticateDetails, () =>
                this.fetchAccessToken(
                  {
                    ...client,
                    redirectUri: 'http://some-incorrect-uri.com',
                  },
                  authorizationCodeDetails
                )
              ))
          })
        })

        describe('with incorrect request details', () => {
          registerSetupAndTearDown()

          it('fails with incorrect code', async () =>
            await expextToFailWithStatusAndDataIncluding(400, { error: 'invalid_grant' }, () =>
              this.fetchAccessToken(client, { ...authorizationCodeDetails, authorizationCode: 'invalid-code' })
            ))
        })
      })

      describe('when refreshing access token', () => {
        let refreshTokenDetails: RefreshTokenDetails

        const verifyScopes = (expected: string[], actual: string[]) => {
          if (R.without(expected, actual).length !== 0) {
            fail(expected, actual, `Returned scopes do not match requested. Actual: ${actual}, expected: ${expected}`)
          }
        }

        const registerAccessTokenFetch = () => {
          before('Fetch access and refresh token', async () => {
            const res = await this.fetchAccessToken(client, authorizationCodeDetails)
            refreshTokenDetails = res.refreshTokenDetails
          })
        }

        describe('with valid refresh token', () => {
          describe('with all scopes', () => {
            registerSetupAndTearDown()
            registerAccessTokenFetch()

            it('should get access token', async () => {
              const res = await this.refreshAccessToken(client, refreshTokenDetails)

              if (!res.accessTokenDetails.accessToken) {
                fail('Access token was not returned or was empty')
              }

              verifyScopes(res.accessTokenDetails.scopes, availableScopes)
            })
          })

          describe('with single scope', () => {
            const firstScope = availableScopes.slice(0, 1)
            registerSetupAndTearDown(firstScope)
            registerAccessTokenFetch()

            it('returns same scope', async () => {
              const res = await this.refreshAccessToken(client, refreshTokenDetails)

              if (!res.accessTokenDetails.accessToken) {
                fail('Access token was not returned or was empty')
              }

              verifyScopes(res.accessTokenDetails.scopes, firstScope)
            })
          })
        })

        describe('when reusing refresh token', () => {
          registerSetupAndTearDown()
          registerAccessTokenFetch()

          it('should fail', async () => {
            await this.refreshAccessToken(client, refreshTokenDetails)

            await expextToFailWithStatusAndDataIncluding(400, { error: 'invalid_grant' }, () =>
              this.refreshAccessToken(client, refreshTokenDetails)
            )
          })
        })
      })
    })
  }

  async fetchAccessToken(
    client: Client,
    authorizationCodeDetails: AuthorizationCodeDetails
  ): Promise<AccessTokenResponse> {
    const data = querystring.stringify({
      grant_type: 'authorization_code',
      code: authorizationCodeDetails.authorizationCode,
      redirect_uri: client.redirectUri,
      client_id: client.clientId,
    })

    // tslint:disable-next-line:no-console
    this.debugLog('Requesting access token with data:', data)

    const res = await axios({
      data,
      method: 'POST',
      url: this.oauthProperties.tokenEndpoint(),
      maxRedirects: 0,
      auth: {
        username: client.clientId,
        password: client.clientSecret,
      },
    })
    this.responseLog('Access token response:', res.data)

    if (res.status === 302) {
      throw new Error('Access token responded with a redirect!')
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
      refreshTokenDetails: {
        scopes,
        refreshToken: res.data.refresh_token,
      },
    }
  }

  async refreshAccessToken(client: Client, refreshTokenDetails: RefreshTokenDetails): Promise<AccessTokenResponse> {
    const data = querystring.stringify({
      grant_type: 'refresh_token',
      refresh_token: refreshTokenDetails.refreshToken,
    })

    // tslint:disable-next-line:no-console
    this.debugLog(`Requesting access token with data: ${data}`)

    const res = await axios({
      data,
      method: 'POST',
      url: this.oauthProperties.tokenEndpoint(),
      maxRedirects: 0,
      auth: {
        username: client.clientId,
        password: client.clientSecret,
      },
    })

    const scopes = res.data.scope !== undefined ? res.data.scope.split(' ') : undefined

    return {
      accessTokenDetails: {
        scopes,
        accessToken: res.data.access_token,
        expiresIn: res.data.expires_in,
        tokenType: res.data.token_type,
      },
      refreshTokenDetails: {
        scopes,
        refreshToken: res.data.refresh_token,
      },
    }
  }
}
