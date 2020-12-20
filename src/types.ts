import { CookieJar } from 'tough-cookie'
import { AxiosResponse } from 'axios'

/**
 * @property clientId - OAuth client ID
 * @property clientSecret - OAuth client secret
 * @property redirectUri - OAuth redirect URI
 * @property clientName - Human readable name for the client
 */
export type Client = {
  clientId: string
  clientSecret: string
  redirectUri: string
  clientName: string // TODO: add oauth props?
}

/**
 * Function that returns a OAuth client id. This function should not take arguments.
 */
export type ClientIdGeneratorFn = () => Promise<string>

/**
 * Function that returns a OAuth client secret. This function should not take arguments.
 */
export type ClientSecretGeneratorFn = () => Promise<string>

/**
 * @param [clientIdFn] - OAuth client id generator. Can be omitted / ignored if the backend automatically generates the id.
 * @param [clientSecretFn] - OAuth client secret generator. Can be omitted / ignored if the backend automatically generates the secret.
 */
export type ClientGeneratorFn = (
  clientName: string,
  redirectUri: string,
  scopes?: string[],
  clientIdFn?: ClientIdGeneratorFn,
  clientSecretFn?: ClientSecretGeneratorFn
) => Promise<Client>
export type RemoveClientFn = (clientName: string) => Promise<void>

export type AccountGeneratorFn = () => Promise<UserAccount>
export type RegisterAccountFn = (user: UserAccount) => Promise<void>
export type RemoveAccountFn = (username: string) => Promise<void>
export type ConsentFn = (
  consentPage: AxiosResponse,
  user: UserAccount,
  jar: CookieJar,
  requestedScopes: string[]
) => Promise<URL>
export type LoginFn = (loginPage: AxiosResponse, user: UserAccount, jar: CookieJar) => AxiosResponse

export type UserAccount = {
  username: string
  password: string
}

/**
 * Properties of the OAuth server
 * @property authorizationEndpoint - URL of the authorization endpoint
 * @property tokenEndpoint - URL of the token endpoint
 */
export type OAuthProperties = {
  authorizationEndpoint: () => string
  tokenEndpoint: () => string
  availableScopes: () => string[]
}

/**
 * @property authorizationCode - OAuth authorization code value
 * @property scopes - OAuth scopes
 */
export type AuthorizationCodeDetails = {
  authorizationCode: string
  scopes: string[]
}

/**
 * @property accessToken - OAuth access token
 * @property [scopes] - OAuth scopes
 * @property [expiresIn] - Access token expiry time
 */
export type AccessTokenDetails = {
  accessToken: string
  scopes?: string[]
  expiresIn?: number
  tokenType: string
}

/**
 * @property refreshToken - OAuth refresh token
 * @property [scopes] - OAuth scopes
 */
export type RefreshTokenDetails = {
  refreshToken: string
  scopes?: string[]
}

/**
 * @property accessToken - Returned access token details
 * @property [refreshToken] - Returned refresh token details
 */
export type AccessTokenResponse = {
  accessToken: AccessTokenDetails
  refreshToken?: RefreshTokenDetails
}

export type CaseFn = (description: string, callback: (...args: any[]) => Promise<void>) => void
export type SuiteFn = (description: string, callback: (...args: any[]) => void) => void
export type SetupFn = (description: string, callback: (...args: any[]) => Promise<void>) => void
export type TeardownFn = (description: string, callback: (...args: any[]) => Promise<void>) => void
export type FailFn<T> = (actual?: T, expected?: T, message?: string) => void

export type TestFunctions = {
  it: CaseFn
  step: CaseFn
  describe: SuiteFn
  before: SetupFn
  after: TeardownFn
  fail: FailFn<any>
}

/**
 * @property run - Run all phases of the test i.e. authorization code, access token and refresh token requests. Returns null if successful and an error object if not.
 * @property getchAuthorizationCode - Test authorization code fetching
 * @property fetchAccessToken - Test access token fetching
 * @property fetchRefreshToken - Test refresh token fetching
 */
export type AuthorizationCodeGrantTester = {
  register: (testFunctions: TestFunctions) => void
  fetchAuthorizationCode: () => Promise<AuthorizationCodeDetails>
  fetchAccessToken: (details: AccessTokenDetails) => Promise<AccessTokenResponse>
  fetchRefreshToken: (details: RefreshTokenDetails) => Promise<AccessTokenResponse>
  cleanup: () => Promise<void>
}
