import { ClientGeneratorFn, OAuthProperties, RemoveClientFn, TestFunctions } from './types'

export default abstract class OAuth2Tester {
  protected oauthProperties: OAuthProperties
  protected clientGenerator: ClientGeneratorFn
  protected removeClient: RemoveClientFn

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
}
