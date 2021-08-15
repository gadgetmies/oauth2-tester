# OAuth2 Server Tester

Opinionated OAuth2 server tester. Very much a work in progress.

Currently building support for testing Authorization Code Grant Flow with PKCE.

## Usage
```ts
import { AuthorizationCodeGrantTester } from 'oauth2-tester';
import { it, describe, before, after } from 'mocha'
import { step } from 'mocha-steps'
import { assert } from 'chai'

const serverRoot = 'http://localhost:3000'

const runners = new AuthorizationCodeGrantTester(
  {
    authorizationEndpoint: () => serverRoot + '/oauth2/authorize',
    tokenEndpoint: () => serverRoot + '/oauth2/token',
    availableScopes: () => ['read']
  },
  {
    clientGenerator,
    removeClient
  },
  {
    accountGenerator,
    registerAccount,
    removeAccount,
    login,
    consent
  }
)

const testFunctions = { describe, it, step, before, after, fail: assert.fail }
runners.register(testFunctions)

// Register tests for resources secured with OAuth
runners.registerResourceRequestTests(['exam:write'], testFunctions, [
  async requestWithAccessToken => {
    it('should create resource when POSTing', async () => {
      const res = await requestWithAccessToken({
        data: {},
        method: 'POST',
        url: serverRoot + '/resource/a'
      })
      ...
    })
  }
])
```

## Debugging

The library uses the [debug](https://www.npmjs.com/package/debug) library for debug logging. To enable logging of authorization and access token request details, include `oauth2-tester` in the `DEBUG` environment variable.

The library uses [axios](https://www.npmjs.com/package/axios) to make HTTP requests and [axios-debug-log](https://www.npmjs.com/package/axios-debug-log) to enable debugging of the requests. To enable logging of HTTP requests include `axios` in the `DEBUG` environment variable.

To enable debug logging of multiple libraries include the names in the `DEBUG` separated with spaces or commas e.g. `DEBUG=axios,oauth2-tester`. For further details refer to the [debug library README](https://github.com/visionmedia/debug#readme).
