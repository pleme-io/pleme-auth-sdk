/**
 * Apollo Auth Link Factory
 *
 * Creates an Apollo Link that adds authentication headers to requests.
 * Properly handles auth-exempt operations (login, register, refresh).
 */

import type { ApolloLink } from '@apollo/client'
import { setContext } from '@apollo/client/link/context'
import { getMainDefinition } from '@apollo/client/utilities'
import { isAuthExemptOperation } from './constants'

/**
 * Configuration for creating an auth link
 */
export interface AuthLinkConfig {
  /**
   * Function to get the current access token
   * Should return null if no token is available
   */
  getAccessToken: () => string | null

  /**
   * Optional API key for staging/development environments
   */
  getApiKey?: () => string | null

  /**
   * Header name for the authorization token
   * @default 'Authorization'
   */
  authorizationHeader?: string

  /**
   * Header name for the API key
   * @default 'x-api-key'
   */
  apiKeyHeader?: string

  /**
   * Token type prefix (e.g., 'Bearer')
   * @default 'Bearer'
   */
  tokenType?: string
}

/**
 * Create an Apollo Link that adds authentication headers to requests
 *
 * FEATURES:
 * - Skips Authorization header for exempt operations (Login, Register, RefreshToken)
 * - Uses provided getAccessToken function for consistent token access
 * - Supports optional API key for staging environments
 *
 * @param config - Configuration for the auth link
 * @returns Apollo Link for authentication
 *
 * @example
 * ```typescript
 * import { createAuthLink } from '@pleme/auth-sdk'
 * import { tokenManager } from '@pleme/auth-sdk'
 *
 * const authLink = createAuthLink({
 *   getAccessToken: () => tokenManager.getAccessToken(),
 *   getApiKey: () => config.apiKey(),
 * })
 *
 * const client = new ApolloClient({
 *   link: from([errorLink, retryLink, authLink, httpLink]),
 *   cache: new InMemoryCache(),
 * })
 * ```
 */
export function createAuthLink(config: AuthLinkConfig): ApolloLink {
  const {
    getAccessToken,
    getApiKey,
    authorizationHeader = 'Authorization',
    apiKeyHeader = 'x-api-key',
    tokenType = 'Bearer',
  } = config

  return setContext((operation, { headers }) => {
    const newHeaders: Record<string, string> = {
      ...headers,
    }

    // Get operation name from the query definition
    const definition = getMainDefinition(operation.query)
    const operationName =
      definition.kind === 'OperationDefinition' ? definition.name?.value : undefined

    // Skip Authorization header for exempt operations (refresh, login, register)
    // These operations don't need the access token and sending an expired one causes issues
    const isExempt = isAuthExemptOperation(operationName)

    if (!isExempt) {
      const token = getAccessToken()

      // Only add authorization header if token exists (empty header causes issues)
      if (token) {
        newHeaders[authorizationHeader] = `${tokenType} ${token}`
      }
    }

    // Add API key for staging environment (if configured)
    if (getApiKey) {
      const apiKey = getApiKey()
      if (apiKey) {
        newHeaders[apiKeyHeader] = apiKey
      }
    }

    return { headers: newHeaders }
  })
}
