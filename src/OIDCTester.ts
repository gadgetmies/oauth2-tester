import {
  AccessTokenResponse,
  AccountGeneratorFn,
  AuthorizationCodeDetails,
  Client,
  ClientGeneratorFn,
  ConsentFn,
  LoginFn,
  OIDCProperties,
  RegisterAccountFn,
  RemoveAccountFn,
  RemoveClientFn,
  TestFunctions,
  UserAccount,
} from './types'
import { AuthorizationCodeGrantWithPKCETester } from './AuthorizationCodeGrantWithPKCETester'
import { SharedAuthorizationCodeGrantTesterOptions } from './SharedAuthorizationCodeGrantTester'
import * as uuid from 'uuid'
import * as jose from 'jose'
import axios from 'axios'
import * as toughCookie from 'tough-cookie'

export class OIDCTester extends AuthorizationCodeGrantWithPKCETester {
  protected oidcProperties: OIDCProperties

  constructor(
    oidcProperties: OIDCProperties,
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
    options: SharedAuthorizationCodeGrantTesterOptions = { useRefreshTokens: false }
  ) {
    super(oidcProperties, client, user, options, { codeChallengeMethod: 'S256' })
    this.oidcProperties = oidcProperties
  }

  register(testFunctions: TestFunctions) {
    const { describe, it, step, before, after, fail } = testFunctions
    const availableScopes = this.oidcProperties.availableScopes()
    const redirectUri = 'https://an-awesome-service.com/'

    describe('OpenID Connect', () => {
      super.register(testFunctions)

      describe('OIDC specific tests', () => {
        const clientName = uuid.v4()
        let client: Client
        let user: UserAccount

        before('Generate OAuth client', async () => {
          client = await this.clientGenerator(clientName, redirectUri, [...availableScopes, 'openid'])
        })

        after('Remove OAuth client', async () => {
          await this.removeClient(clientName)
        })

        describe('when requesting with openid scope', () => {
          let authorizationCodeDetails: AuthorizationCodeDetails
          let accessTokenResponse: AccessTokenResponse
          const nonce = uuid.v4()

          before('Generate user details', async () => {
            user = await this.accountGenerator()
          })

          before('Register user', async () => {
            await this.registerAccount(user)
            this.cookieJars[user.username] = new toughCookie.CookieJar()
          })

          after('Remove user', async () => await this.removeUser(user))

          step('Fetch authorization code with openid scope and nonce', async () => {
            authorizationCodeDetails = await this.fetchAuthorizationCode(client, user, {
              scopes: [...availableScopes, 'openid'],
              nonce,
            })
          })

          step('Fetch access token and verify id_token presence', async () => {
            accessTokenResponse = await this.fetchAccessToken(client, authorizationCodeDetails, { user })
            if (!accessTokenResponse.accessTokenDetails.idToken) {
              fail('ID Token was not returned when openid scope was requested')
            }
          })

          it('should have valid ID Token claims', async () => {
            const idToken = accessTokenResponse.accessTokenDetails.idToken!
            const decoded = jose.decodeJwt(idToken)

            if (decoded.iss !== this.oidcProperties.issuer()) {
              fail(decoded.iss, this.oidcProperties.issuer(), 'Invalid issuer in ID Token')
            }

            const aud = Array.isArray(decoded.aud) ? decoded.aud : [decoded.aud]
            if (!aud.includes(client.clientId)) {
              fail(aud, client.clientId, 'Invalid audience in ID Token')
            }

            if (decoded.nonce !== nonce) {
              fail(decoded.nonce, nonce, 'Invalid nonce in ID Token')
            }

            if (!decoded.sub) {
              fail('Missing sub claim in ID Token')
            }

            const now = Math.floor(Date.now() / 1000)
            if (decoded.exp && decoded.exp < now) {
              fail(decoded.exp, now, 'ID Token has expired')
            }

            if (!decoded.iat) {
              fail('Missing iat claim in ID Token')
            }
          })

          it('should not return ID Token when openid scope is not requested', async () => {
            const authCodeDetails = await this.fetchAuthorizationCode(client, user, {
              scopes: availableScopes,
            })
            const tokenResponse = await this.fetchAccessToken(client, authCodeDetails, { user })
            if (tokenResponse.accessTokenDetails.idToken) {
              fail('ID Token was returned even though openid scope was not requested')
            }
          })

          it('should fetch UserInfo with access token', async () => {
            const res = await axios.get(this.oidcProperties.userInfoEndpoint(), {
              headers: {
                Authorization: `Bearer ${accessTokenResponse.accessTokenDetails.accessToken}`,
              },
            })

            if (res.status !== 200) {
              fail(res.status, 200, 'UserInfo request failed')
            }

            const idTokenDecoded = jose.decodeJwt(accessTokenResponse.accessTokenDetails.idToken!)
            if (res.data.sub !== idTokenDecoded.sub) {
              fail(res.data.sub, idTokenDecoded.sub, 'UserInfo sub claim does not match ID Token sub claim')
            }
          })

          it('should fail to fetch UserInfo with invalid access token', async () => {
            try {
              await axios.get(this.oidcProperties.userInfoEndpoint(), {
                headers: {
                  Authorization: `Bearer invalid-token`,
                },
              })
              fail('UserInfo request should have failed with invalid token')
            } catch (e) {
              if (!e.response) {
                throw e
              }
              if (e.response.status !== 401) {
                fail(e.response.status, 401, 'UserInfo request failed with wrong status code')
              }
            }
          })

          it('should fail to fetch UserInfo without authorization header', async () => {
            try {
              await axios.get(this.oidcProperties.userInfoEndpoint())
              fail('UserInfo request should have failed without authorization header')
            } catch (e) {
              if (!e.response) {
                throw e
              }
              if (e.response.status !== 401) {
                fail(e.response.status, 401, 'UserInfo request failed with wrong status code')
              }
            }
          })
        })
      })
    })
  }
}
