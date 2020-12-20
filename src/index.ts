import * as uuid from 'uuid'
import * as querystring from 'querystring'

import axios, { AxiosError, AxiosResponse } from 'axios'
import axiosCookiejarSupport from 'axios-cookiejar-support'

axiosCookiejarSupport(axios)
import * as toughCookie from 'tough-cookie'

import {
  OAuthProperties,
  ClientGeneratorFn,
  RemoveClientFn,
  RegisterAccountFn,
  LoginFn,
  ConsentFn,
  RemoveAccountFn,
  Client,
  UserAccount,
  AuthorizationCodeDetails,
  AccessTokenResponse,
  TestFunctions,
  AccountGeneratorFn,
} from './types'

const redirectUri = 'http://localhost:5000' // TODO: specify in suites

export class AuthorizationCodeGrantTester {
  private oauthProperties: OAuthProperties // TODO: should this include availableScopes? Those are not needed when requesting tokens
  private clientGenerator: ClientGeneratorFn
  private removeClient: RemoveClientFn
  private options: object // TODO
  private registerAccount: RegisterAccountFn
  private login: LoginFn
  private consent: ConsentFn
  private removeAccount: RemoveAccountFn
  private cookieJars: { [x: string]: toughCookie.CookieJar } = {}
  private accountGenerator: AccountGeneratorFn

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
    options: {
      allowHttp: boolean
      grants: string[]
      scopes: string[]
    } = {
      allowHttp: false,
      grants: [],
      scopes: [],
    }
  ) {
    this.oauthProperties = oauthProperties
    this.clientGenerator = client.clientGenerator
    this.removeClient = client.removeClient
    this.registerAccount = user.registerAccount
    this.removeAccount = user.removeAccount
    this.login = user.login
    this.consent = user.consent
    this.options = options
    this.accountGenerator = user.accountGenerator

    console.log(oauthProperties)
  }

  register({ describe, it, step, before, after, fail }: TestFunctions) {
    // const expectToBeResolvedWith = async (
    //   callback: () => Promise<AxiosResponse>,
    //   ...assertions: ((res: AxiosResponse) => Promise<void>)[]
    // ) => {
    //   const res = await callback()
    //   for (const assert of assertions) {
    //     await assert(res)
    //   }
    // }

    // TODO: move to another scope
    const expectToFail = async (callback: () => Promise<any>, ...assertions: ((e: Error) => Promise<void>)[]) => {
      try {
        await callback()
      } catch (e) {
        for (const assert of assertions) {
          await assert(e)
        }
        return
      }

      fail(true, false, 'Expected to fail')
    }

    const withStatus = (status: number) => async (e: AxiosResponse): Promise<void> => {
      if (e.status !== status) {
        fail(e.status, status, `Wrong HTTP status: ${e.status}. Expected: ${status}`)
      }
    }

    const withData = (data: { [k: string]: string }) => async (e: AxiosResponse) => {
      if (e.data !== data) {
        fail(e.data, data, `Wrong query: ${e.data}. Expected: ${JSON.stringify(data, null, 2)}`)
      }
    }

    const withLocation = (location: string) => async (e: AxiosResponse) => {
      if (e.headers.location !== location) {
        fail(e.headers.location, location, `Expected location to be ${location}, but was: ${e.headers.location}`)
      }
    }

    const expectRedirectWithLocation = (location: string, callback: () => Promise<any>) =>
      expectToFail(callback, withResponse(withStatus(302)), withResponse(withLocation(location)))

    const withResponse = (callback: (e: AxiosResponse) => Promise<void>) => (e: AxiosError) => callback(e.response)

    const expectToFailWithStatus = async (status: number, callback: () => Promise<any>): Promise<void> =>
      expectToFail(callback, withResponse(withStatus(status)))

    describe('when request details are valid', () => {
      const clientName = uuid.v4()
      let client

      before('Generate OAuth client', async () => {
        client = await this.clientGenerator(clientName, redirectUri, this.oauthProperties.availableScopes())
      })

      describe('when using all scopes', () => {
        let user
        let authorizationCode
        let accessTokenResponse

        before('Generate user details', async () => {
          user = await this.accountGenerator()
        })

        before('Register user', async () => {
          await this.registerAccount(user)
          this.cookieJars[user.username] = new toughCookie.CookieJar()
        })

        step('Fetch authorization code for all scopes', async () => {
          authorizationCode = await this.fetchAuthorizationCode(
            this.oauthProperties,
            client,
            user,
            this.oauthProperties.availableScopes()
          )
        })

        step('Fetch access token', async () => {
          accessTokenResponse = await this.fetchAccessToken(client, authorizationCode)
        })

        after('Remove user', async () => {
          await this.removeAccount(user.username)
        })
      })

      describe('when using single scope', () => {
        let user

        before('Generate user details', async () => {
          user = await this.accountGenerator()
        })

        before('Register user', async () => {
          await this.registerAccount(user)
          this.cookieJars[user.username] = new toughCookie.CookieJar()
        })

        for (const scope of this.oauthProperties.availableScopes()) {
          let authorizationCode
          let accessTokenResponse

          describe(`with scope: ${scope}`, () => {
            step(`Fetch authorization code`, async () => {
              authorizationCode = await this.fetchAuthorizationCode(this.oauthProperties, client, user, [scope])
            })

            step('Fetch access token', async () => {
              accessTokenResponse = await this.fetchAccessToken(client, authorizationCode)
            })
          })
        }

        after('Remove user', async () => {
          await this.removeAccount(user.username)
        })
      })

      after('Remove OAuth client', async () => {
        await this.removeClient(clientName)
      })
    })

    describe('when request details are valid but', () => {
      const clientName = uuid.v4() // TODO: use generator function instead
      let client
      const user = {
        username: uuid.v4(), // TODO: use generator function instead
        password: 'test',
      }
      let authorizationCode
      let accessTokenResponse

      before('Generate OAuth client', async () => {
        client = await this.clientGenerator(clientName, 'http://localhost:5000', this.oauthProperties.availableScopes())
      })

      before('Register user', async () => {
        await this.registerAccount(user)
        this.cookieJars[user.username] = new toughCookie.CookieJar()
      })

      before('Fetch authorization code', async () => {
        authorizationCode = await this.fetchAuthorizationCode(
          this.oauthProperties,
          client,
          user,
          this.oauthProperties.availableScopes()
        )
      })

      before('Fetch access token', async () => {
        accessTokenResponse = await this.fetchAccessToken(client, authorizationCode)
      })

      it('fails if authorization code is reused', () =>
        expectRedirectWithLocation(
          `${redirectUri}/?error=invalid_grant&error_description=Invalid%20authorization%20code`,
          () => this.fetchAccessToken(client, authorizationCode)
        ))

      after('Remove user', async () => {
        await this.removeAccount(user.username)
      })

      after('Remove OAuth client', async () => {
        await this.removeClient(clientName)
      })
    })

    /* TODO: cases
     * User does not consent
     * Verify token type?
     * Incorrect token type request?
     * Refresh token
     * State parameter (also on errors)
     * Check expiresIn
     * Embedded browser / frame (possible to test? requires a web server?)
     * CSRF against redirect-uri?
     * DoS attack that exhaust resources
     * PKCE
     *   * invalid verifier
     *   * Without verifier
     *
     */

    describe('when request details are invalid', () => {
      const clientName = uuid.v4()
      let client
      const user = {
        username: uuid.v4(),
        password: 'test',
      }

      before('Generate OAuth client', async () => {
        client = await this.clientGenerator(clientName, 'http://localhost:5000', this.oauthProperties.availableScopes())
      })

      before('Register user', async () => {
        await this.registerAccount(user)
        this.cookieJars[user.username] = new toughCookie.CookieJar()
      })

      describe('when fetching authorization code', () => {
        it('fails if scope is invalid', () =>
          expectToFailWithStatus(400, () =>
            this.fetchAuthorizationCode(this.oauthProperties, client, user, ['invalid-scope'])
          ))

        it('fails if user is invalid', () =>
          expectToFailWithStatus(401, () =>
            this.fetchAuthorizationCode(
              this.oauthProperties,
              client,
              {
                username: 'foo',
                password: 'bar',
              },
              this.oauthProperties.availableScopes()
            )
          ))

        it('fails if redirect URI port is incorrect', () =>
          expectToFailWithStatus(400, () =>
            this.fetchAuthorizationCode(
              this.oauthProperties,
              { ...client, redirectUri: 'http://localhost:5001' },
              user,
              this.oauthProperties.availableScopes()
            )
          ))

        it('fails if redirect URI is incorrect', () =>
          expectToFailWithStatus(400, () =>
            this.fetchAuthorizationCode(
              this.oauthProperties,
              { ...client, redirectUri: 'http://some-incorrect-uri.com' },
              user,
              this.oauthProperties.availableScopes()
            )
          ))
      })

      describe('when fetching access token', () => {
        let authorizationCode

        before('fetch authorization code', async () => {
          authorizationCode = await this.fetchAuthorizationCode(
            this.oauthProperties,
            client,
            user,
            this.oauthProperties.availableScopes()
          )
        })

        it('fails with incorrect code', () =>
          // TODO: add ability to provide valid authorizationCodes
          expectToFailWithStatus(400, () =>
            this.fetchAccessToken(client, { authorizationCode: 'invalid-code', scopes: [] })
          ))

        it('fails with incorrect client id', () =>
          // TODO: add ability to provide valid authorizationCodes
          expectToFailWithStatus(403, () =>
            this.fetchAccessToken({ ...client, clientId: 'invalid-client-id' }, authorizationCode)
          ))

        it('fails with incorrect client secret', () =>
          // TODO: add ability to provide valid authorizationCodes
          expectToFailWithStatus(403, () =>
            this.fetchAccessToken({ ...client, clientSecret: 'invalid-client-secret' }, authorizationCode)
          ))

        it('fails with incorrect redirect URI port', () =>
          // TODO: add ability to provide valid authorizationCodes
          expectToFailWithStatus(403, () =>
            this.fetchAccessToken({ ...client, redirectUri: 'http://localhost:5001' }, authorizationCode)
          ))

        it('fails with incorrect redirect URI', () =>
          // TODO: add ability to provide valid authorizationCodes
          expectToFailWithStatus(403, () =>
            this.fetchAccessToken({ ...client, redirectUri: 'http://some-incorrect-uri.com' }, authorizationCode)
          ))
      })

      after('Remove user', async () => {
        await this.removeAccount(user.username)
      })

      after('Remove OAuth client', async () => {
        await this.removeClient(clientName)
      })
    })
  }

  async requestAuthorizationCode(
    oauthProperties: OAuthProperties,
    client: Client,
    user: UserAccount,
    scopes: string[]
  ): Promise<AuthorizationCodeDetails> {
    const jar = this.cookieJars[user.username]
    const res = await axios({
      jar,
      url: oauthProperties.authorizationEndpoint(),
      method: 'GET',
      withCredentials: true,
      params: {
        client_id: client.clientId,
        redirect_uri: client.redirectUri,
        scope: scopes.join(' '),
        response_type: 'code', // TODO: add state?
      },
    })

    const config = res.config
    // @ts-ignore

    const loginResponse = await this.login(res, user, jar)
    const redirectUri = await this.consent(loginResponse, user, jar, scopes) // TODO: assert scopes

    // @ts-ignore
    const authorizationCode = new URL(redirectUri).searchParams.get('code')

    return {
      authorizationCode,
      scopes,
    }
  }

  async fetchAuthorizationCode(
    oauthProperties: OAuthProperties,
    client: Client,
    user: UserAccount,
    scopes: string[]
  ): Promise<AuthorizationCodeDetails> {
    return await this.requestAuthorizationCode(oauthProperties, client, user, scopes)
  }

  async fetchAccessToken(client: Client, authorizationCode: AuthorizationCodeDetails): Promise<AccessTokenResponse> {
    const res = await axios({
      method: 'POST',
      url: this.oauthProperties.tokenEndpoint(),
      maxRedirects: 0,
      auth: {
        username: client.clientId,
        password: client.clientSecret,
      },
      data: querystring.stringify({
        grant_type: 'authorization_code',
        code: authorizationCode.authorizationCode,
        redirect_uri: client.redirectUri,
        client_id: client.clientId,
      }),
    })

    const scopes = res.data.scope !== undefined ? res.data.scope.split(' ') : undefined

    return {
      accessToken: {
        scopes,
        accessToken: res.data.access_token,
        expiresIn: res.data.expires_in,
        tokenType: res.data.token_type,
      },
      refreshToken: {
        scopes,
        refreshToken: res.data.refresh_token,
      },
    }
  }

  async fetchRefreshToken(): Promise<AccessTokenResponse> {
    return Promise.resolve({
      accessToken: {
        accessToken: '',
        expiresIn: 3600,
        scopes: [''],
        tokenType: '',
      },
      refreshToken: {
        refreshToken: '',
        scopes: [],
      },
    })
  }

  async cleanup() {
    return
  }
}

// const testAuthorizationCodeGrantWithPKCE = () => {}
