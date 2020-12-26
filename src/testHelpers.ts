import { AxiosError, AxiosResponse } from 'axios'
import { FailFn } from './types'
import aggregateError = require('aggregate-error')

export class TestHelpers {
  private readonly fail: FailFn<any>
  constructor(fail) {
    this.fail = fail
  }

  anyPass<T>(...callbacks: ((arg: T) => Promise<void>)[]) {
    return async (arg: T) => {
      const errors: Error[] = []
      for (const cb of callbacks) {
        try {
          await cb(arg)
          return
        } catch (e) {
          errors.push(e)
        }
      }

      throw new aggregateError(errors)
    }
  }

  expectToSucceed = async (
    callback: () => Promise<AxiosResponse>,
    ...assertions: ((res: AxiosResponse) => Promise<void>)[]
  ) => {
    const res = await callback()
    for (const assert of assertions) {
      await assert(res)
    }
  }

  // TODO: move to another scope
  expectToFail = async (callback: () => Promise<any>, ...assertions: ((e: Error) => Promise<void>)[]) => {
    try {
      await callback()
    } catch (e) {
      for (const assert of assertions) {
        await assert(e)
      }
      return
    }

    this.fail(true, false, 'Expected to fail')
  }

  withStatus = (status: number) => async (res: AxiosResponse): Promise<void> => {
    if (res.status !== status) {
      this.fail(res.status, status, `Wrong HTTP status: ${res.status}. Expected: ${status}`)
    }
  }

  withData = (data: { [k: string]: string }) => async (res: AxiosResponse) => {
    if (res.data !== data) {
      this.fail(res.data, data, `Wrong data: '${JSON.stringify(res.data)}'. Expected: ${JSON.stringify(data, null, 2)}`)
    }
  }

  withQuery = (query: { [k: string]: string }) => async (res: AxiosResponse) => {
    const url = new URL(res.headers.location)
    Object.entries(query).forEach(([key, value]) => {
      const actual = url.searchParams.get(key)
      if (actual !== value) {
        this.fail(
          `${key}=${actual}`,
          `${key}=${value}`,
          `Expected query parameters to be ${Object.entries(query)
            .map((e) => e.join('='))
            .join('&')}, was: ${url.searchParams.toString()}`
        )
      }
    })
  }

  withLocation = (expectedLocation: string, includeQuery = true) => async (res: AxiosResponse) => {
    const actualLocation = includeQuery ? res.headers.location : res.headers.location.split('?')[0]
    const rest = res.headers.location.replace(actualLocation, '')
    const restString = rest ? `[${rest}]` : ''
    if (actualLocation !== expectedLocation) {
      this.fail(
        actualLocation,
        expectedLocation,
        `Expected location to match ${expectedLocation} ${
          !includeQuery ? '(excluding query)' : ''
        }. Location was: ${actualLocation}${restString}`
      )
    }
  }

  withLocationPattern = (pattern: RegExp) => async (res: AxiosResponse) => {
    if (!res.headers.location.match(pattern)) {
      this.fail(
        res.headers.location,
        pattern,
        `Expected location to match ${pattern}. Location was: ${res.headers.location}`
      )
    }
  }

  expectRedirectWithLocation = (location: RegExp, callback: () => Promise<AxiosResponse>) =>
    this.expectToSucceed(callback, this.withStatus(302), this.withLocationPattern(location))

  expectErrorRedirectToIncludeQuery = (
    redirectUrl: string,
    query: { [k: string]: string },
    callback: () => Promise<any>
  ) =>
    this.expectToFail(
      callback,
      this.withErrorResponse(this.withStatus(302)),
      this.withErrorResponse(this.withLocation(redirectUrl, false)),
      this.withErrorResponse(this.withQuery(query))
    )

  expectRedirectToIncludeQuery = (redirectUrl: string, query: { [k: string]: string }, callback: () => Promise<any>) =>
    this.expectToSucceed(
      callback,
      this.withResponse(this.withStatus(302)),
      this.withResponse(this.withLocation(redirectUrl, false)),
      this.withResponse(this.withQuery(query))
    )

  expectErrorRedirectWithLocation = (location: RegExp, callback: () => Promise<any>) =>
    this.expectToFail(
      callback,
      this.withErrorResponse(this.withStatus(302)),
      this.withErrorResponse(this.withLocationPattern(location))
    )

  withErrorResponse = (callback: (r: AxiosResponse) => Promise<void>) => (e: AxiosError) => callback(e.response)
  withResponse = (callback: (r: AxiosResponse) => Promise<void>) => (r: AxiosResponse) => callback(r)

  withHeaders = (expectedHeaders: { [k: string]: string | RegExp }) => async (res: AxiosResponse) => {
    const stringifyHeaders = (headers) =>
      Object.entries(headers)
        .map(([k, v]) => `${k}=${v}`)
        .join(', ')

    Object.entries(expectedHeaders).forEach(([key, expectedValueOrPattern]) => {
      const actual = res.headers[key]
      if (
        actual === undefined ||
        (expectedValueOrPattern instanceof RegExp
          ? !actual.match(expectedValueOrPattern)
          : actual !== expectedValueOrPattern)
      ) {
        this.fail(
          actual,
          expectedValueOrPattern,
          `Expected response to have headers: ${stringifyHeaders(expectedHeaders)}, but instead got: ${stringifyHeaders(
            res.headers
          )}`
        )
      }
    })
  }

  expectToFailWithStatus = async (status: number, callback: () => Promise<any>): Promise<void> =>
    this.expectToFail(callback, this.withErrorResponse(this.withStatus(status)))

  expectToFailWithAnyStatus = async (statuses: number[], callback: () => Promise<any>): Promise<void> =>
    this.expectToFail(
      callback,
      this.withErrorResponse(this.anyPass(...statuses.map((status) => this.withStatus(status))))
    )

  expectToBeUnauthorized = async (
    { authenticationType, realm, charset }: { authenticationType: string; realm: RegExp; charset?: string } = {
      authenticationType: 'Basic',
      realm: /.*/,
    },
    callback: () => Promise<any>
  ): Promise<void> =>
    this.expectToFail(
      callback,
      this.withErrorResponse(this.withStatus(401)),
      this.withErrorResponse(
        this.withHeaders({
          'www-authenticate': new RegExp(
            `${authenticationType} realm="${realm.source}"${charset !== undefined ? ` charset="${charset}"` : ''}`
          ),
        })
      )
    )
}
