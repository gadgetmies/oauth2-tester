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

runners.register({ describe, it, step, before, after, fail: assert.fail })
```
