import { CookieJar } from 'tough-cookie'
import { AxiosPromise, AxiosRequestConfig, AxiosResponse } from 'axios'

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
  shouldConsent: boolean,
  consentPage: AxiosResponse,
  user: UserAccount,
  jar: CookieJar,
  requestedScopes: string[]
) => Promise<AxiosResponse>
export type LoginFn = (loginPage: AxiosResponse, user: UserAccount, jar: CookieJar) => AxiosResponse

export type UserAccount = {
  username: string
  password: string
}

export type OAuthProperties = {
  authorizationEndpoint: () => string
  tokenEndpoint: () => string
  availableScopes: () => string[]
}

export type AuthorizationCodeDetails = {
  authorizationCode: string
  scopes: string[]
}

export type AccessTokenDetails = {
  accessToken: string
  scopes?: string[]
  expiresIn?: number
  tokenType: string
}

export type RefreshTokenDetails = {
  refreshToken: string
  scopes?: string[]
}

export type AccessTokenResponse = {
  accessTokenDetails: AccessTokenDetails
  refreshTokenDetails?: RefreshTokenDetails
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

export type RequestWithAccessTokenFn = (config: AxiosRequestConfig, overrideAccessToken?: string) => AxiosPromise

export type ResourceRequestTestFn = (
  requestWithAccessToken: RequestWithAccessTokenFn
) => void

export type AuthorizationCodeRequestOptions = {
  shouldConsent?: boolean
  scopes?: string[]
  extraParams?: {
    [k: string]: string
  }
}

export type AccessTokenRequestOptions = {
  extraParams?: {
    [k: string]: string
  }
}
