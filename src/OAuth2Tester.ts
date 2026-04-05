import { ClientGeneratorFn, OAuthProperties, RemoveClientFn, TestFunctions } from './types'
import 'axios-debug-log'
import debug from "debug";

export default abstract class OAuth2Tester {
  public oauthProperties: OAuthProperties
  public clientGenerator: ClientGeneratorFn
  public removeClient: RemoveClientFn

  protected constructor(
    oauthProperties: OAuthProperties,
    client: {
      clientGenerator: ClientGeneratorFn
      removeClient: RemoveClientFn
    }
  ) {
    this.oauthProperties = oauthProperties
    this.clientGenerator = client.clientGenerator
    this.removeClient = client.removeClient
  }

  abstract register(testFunctions: TestFunctions): void

  protected debugLog = debug('oauth2-tester')
  protected responseLog = debug('oauth2-tester:response')
}
