import {
  Client,
  IDTokenDetails,
  OIDCProperties,
  TestFunctions,
  UserAccount,
} from './types'
import { SharedAuthorizationCodeGrantTester } from './SharedAuthorizationCodeGrantTester'
import { TestHelpers } from './testHelpers'
import axios from 'axios'
import * as uuid from 'uuid'
import * as toughCookie from 'tough-cookie'

export class OIDCTester {
  constructor(
    private oidcProperties: OIDCProperties,
    private oauthTester: SharedAuthorizationCodeGrantTester
  ) {}

  registerDiscoveryTests(testFunctions: TestFunctions) {
    const { describe, it } = testFunctions
    const helpers = new TestHelpers(testFunctions.fail)

    if (!this.oidcProperties.discoveryEndpoint) {
      return
    }

    describe('OIDC Discovery', () => {
      it('should return valid discovery document', async () => {
        const res = await axios.get(this.oidcProperties.discoveryEndpoint!())
        helpers.withStatus(200)(res)
        const discoveryDocument = res.data

        const requiredFields = [
          'issuer',
          'authorization_endpoint',
          'token_endpoint',
          'response_types_supported',
          'subject_types_supported',
          'id_token_signing_alg_values_supported',
        ]

        for (const field of requiredFields) {
          if (!discoveryDocument[field]) {
            testFunctions.fail(undefined, field, `Discovery document missing required field: ${field}`)
          }
        }

        if (discoveryDocument.issuer !== this.oidcProperties.issuer()) {
          testFunctions.fail(discoveryDocument.issuer, this.oidcProperties.issuer(), 'Issuer mismatch in discovery document')
        }
      })
    })
  }

  registerIDTokenTests(testFunctions: TestFunctions) {
    const { describe, it, before, after, fail } = testFunctions
    const redirectUri = 'https://an-awesome-service.com/'
    const clientName = uuid.v4()
    let client: Client
    let user: UserAccount

    describe('OIDC ID Token', () => {
      before('Generate OAuth client', async () => {
        client = await this.oauthTester.clientGenerator(clientName, redirectUri, ['openid'])
      })

      before('Register user', async () => {
        user = await this.oauthTester.accountGenerator()
        await this.oauthTester.registerAccount(user)
        this.oauthTester.cookieJars[user.username] = new toughCookie.CookieJar()
      })

      after('Remove user', async () => {
        await this.oauthTester.removeUser(user)
      })

      after('Remove OAuth client', async () => {
        await this.oauthTester.removeClient(clientName)
      })

      it('should return id_token when openid scope is requested', async () => {
        const authCodeDetails = await this.oauthTester.fetchAuthorizationCode(client, user, {
          scopes: ['openid'],
        })

        const accessTokenResponse = await this.oauthTester.fetchAccessToken(client, authCodeDetails, { user })

        if (!accessTokenResponse.idTokenDetails) {
          fail('id_token was not returned or could not be decoded')
        }

        const idToken = accessTokenResponse.idTokenDetails!
        this.validateIDToken(idToken, client, fail)
      })
    })
  }

  private validateIDToken(idToken: IDTokenDetails, client: Client, fail: any) {
    if (idToken.iss !== this.oidcProperties.issuer()) {
      fail(idToken.iss, this.oidcProperties.issuer(), 'ID Token issuer mismatch')
    }

    if (!idToken.sub) {
      fail(undefined, 'sub', 'ID Token missing sub claim')
    }

    const audience = Array.isArray(idToken.aud) ? idToken.aud : [idToken.aud]
    if (!audience.includes(client.clientId)) {
      fail(audience, client.clientId, 'ID Token audience mismatch')
    }

    const now = Math.floor(Date.now() / 1000)
    if (idToken.exp < now) {
      fail(idToken.exp, now, 'ID Token expired')
    }

    if (idToken.iat > now + 60) {
      // Allow 1 minute clock skew
      fail(idToken.iat, now, 'ID Token issued in the future')
    }
  }

  registerUserInfoTests(testFunctions: TestFunctions) {
    const { describe, it, before, after, fail } = testFunctions
    const redirectUri = 'https://an-awesome-service.com/'
    const clientName = uuid.v4()
    let client: Client
    let user: UserAccount

    if (!this.oidcProperties.userinfoEndpoint) {
      return
    }

    describe('OIDC UserInfo', () => {
      before('Generate OAuth client', async () => {
        client = await this.oauthTester.clientGenerator(clientName, redirectUri, ['openid'])
      })

      before('Register user', async () => {
        user = await this.oauthTester.accountGenerator()
        await this.oauthTester.registerAccount(user)
        this.oauthTester.cookieJars[user.username] = new toughCookie.CookieJar()
      })

      after('Remove user', async () => {
        await this.oauthTester.removeUser(user)
      })

      after('Remove OAuth client', async () => {
        await this.oauthTester.removeClient(clientName)
      })

      it('should return userInfo consistent with ID Token', async () => {
        const authCodeDetails = await this.oauthTester.fetchAuthorizationCode(client, user, {
          scopes: ['openid'],
        })

        const accessTokenResponse = await this.oauthTester.fetchAccessToken(client, authCodeDetails, { user })
        const accessToken = accessTokenResponse.accessTokenDetails.accessToken
        const idToken = accessTokenResponse.idTokenDetails

        if (!idToken) {
          fail('id_token missing')
          return
        }

        const userInfoRes = await axios.get(this.oidcProperties.userinfoEndpoint!(), {
          headers: { Authorization: `Bearer ${accessToken}` },
        })

        if (userInfoRes.status !== 200) {
          fail(userInfoRes.status, 200, 'UserInfo request failed')
        }

        if (userInfoRes.data.sub !== idToken.sub) {
          fail(userInfoRes.data.sub, idToken.sub, 'UserInfo sub mismatch with ID Token sub')
        }
      })
    })
  }
}
