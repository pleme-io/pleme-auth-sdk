/**
 * Apollo Error Link for XState Auth Machine Integration
 *
 * This error link works with the XState auth machine for handling
 * authentication errors. Unlike the legacy errorLink, it does NOT
 * use RefreshCoordinator - the machine handles refresh internally.
 *
 * ARCHITECTURE:
 * - Machine handles token refresh proactively (60s before expiry)
 * - If UNAUTHENTICATED error occurs, it means refresh failed or token expired
 * - This link signals the machine to attempt refresh or force logout
 */

import { onError, type ErrorLink } from '@apollo/client/link/error'
import { Observable, FetchResult } from '@apollo/client'
import { AUTH_ERROR_CODES, AUTH_HTTP_STATUS } from './constants'

/**
 * Configuration for machine-integrated error link
 */
export interface MachineErrorLinkConfig {
  /**
   * Async function to attempt token refresh via the machine.
   * Should return true if refresh succeeded, false otherwise.
   * The machine handles the actual refresh logic.
   */
  attemptRefresh: () => Promise<boolean>

  /**
   * Function to call when user should be logged out.
   * Should trigger machine's FORCE_LOGOUT event.
   */
  onForceLogout: () => void

  /**
   * Function to get the redirect URL for login.
   * Should preserve the current path for redirect after login.
   */
  getLoginRedirectUrl: () => string

  /**
   * Optional callback for GraphQL errors (for logging/analytics)
   */
  onGraphQLError?: (error: {
    message: string
    path?: readonly (string | number)[]
    extensions?: Record<string, unknown>
    operationName?: string
  }) => void

  /**
   * Optional callback for network errors (for logging/analytics)
   */
  onNetworkError?: (error: Error, operationName?: string) => void

  /**
   * Optional callback for rate limit errors
   */
  onRateLimit?: (retryAfter: number, message: string) => void

  /**
   * Whether to log errors to console
   * @default true in development, false in production
   */
  enableLogging?: boolean
}

/**
 * Check if any GraphQL error is an authentication error (UNAUTHENTICATED only)
 */
function hasAuthenticationError(errors: readonly { extensions?: { code?: unknown } }[]): boolean {
  return errors.some((error) => {
    const code = error.extensions?.code
    return code === AUTH_ERROR_CODES.UNAUTHENTICATED
  })
}

/**
 * Check for rate limit errors in GraphQL response
 */
function findRateLimitError(
  errors: readonly { extensions?: { code?: unknown; retryAfter?: unknown }; message: string }[]
): { retryAfter: number; message: string } | null {
  const rateLimitError = errors.find((error) => {
    const code = error.extensions?.code
    return code === 'TOO_MANY_REQUESTS' || code === 'RATE_LIMIT_EXCEEDED'
  })

  if (rateLimitError) {
    return {
      retryAfter: (rateLimitError.extensions?.retryAfter as number) || 60,
      message: rateLimitError.message || 'Too many requests. Please wait before trying again.',
    }
  }

  return null
}

/**
 * Create an Apollo Error Link for XState auth machine integration
 *
 * FEATURES:
 * - Integrates with XState auth machine for token refresh
 * - Distinguishes UNAUTHENTICATED (refresh) from FORBIDDEN (show error)
 * - Preserves current URL when redirecting to login
 * - Handles rate limiting and network errors
 *
 * @param config - Configuration for the error link
 * @returns Apollo Link for error handling
 *
 * @example
 * ```typescript
 * import { createMachineErrorLink, getAccessToken } from '@pleme/auth-sdk'
 *
 * const errorLink = createMachineErrorLink({
 *   attemptRefresh: async () => {
 *     // Machine handles refresh via REFRESH_TOKEN event
 *     send({ type: 'REFRESH_TOKEN' })
 *     // Wait for machine to complete refresh (check state)
 *     return await waitForRefreshComplete()
 *   },
 *   onForceLogout: () => {
 *     send({ type: 'FORCE_LOGOUT' })
 *   },
 *   getLoginRedirectUrl: () => {
 *     const currentPath = window.location.pathname + window.location.search
 *     return `/login?redirect=${encodeURIComponent(currentPath)}`
 *   },
 * })
 * ```
 */
export function createMachineErrorLink(config: MachineErrorLinkConfig): ErrorLink {
  const {
    attemptRefresh,
    onForceLogout,
    getLoginRedirectUrl,
    onGraphQLError,
    onNetworkError,
    onRateLimit,
    enableLogging = process.env.NODE_ENV !== 'production',
  } = config

  const log = enableLogging
    ? {
        info: (msg: string, data?: unknown) => console.log(`[Apollo] ${msg}`, data || ''),
        error: (msg: string, data?: unknown) => console.error(`[Apollo] ${msg}`, data || ''),
      }
    : { info: () => {}, error: () => {} }

  const redirectToLogin = () => {
    window.location.href = getLoginRedirectUrl()
  }

  const handleAuthError = async (
    operationName: string | undefined,
    forward: Parameters<Parameters<typeof onError>[0]>[0]['forward'],
    operation: Parameters<Parameters<typeof onError>[0]>[0]['operation']
  ): Promise<Observable<unknown> | void> => {
    log.info('⚠️  Authentication error detected - attempting token refresh via machine')

    // Don't try to refresh if this IS the refresh mutation
    if (operationName === 'RefreshToken') {
      log.info('Refresh mutation itself failed - clearing session')
      onForceLogout()
      redirectToLogin()
      return
    }

    try {
      const refreshed = await attemptRefresh()

      if (refreshed) {
        log.info('✅ Token refreshed successfully - retrying operation:', operationName)
        return forward(operation)
      } else {
        log.info('❌ Token refresh failed - clearing session')
        onForceLogout()
        redirectToLogin()
      }
    } catch (error) {
      log.error('Token refresh threw error:', error)
      onForceLogout()
      redirectToLogin()
    }
  }

  return onError(({ graphQLErrors, networkError, operation, forward }) => {
    const operationName = operation.operationName

    if (graphQLErrors) {
      log.info('🚨 GraphQL Errors')
      log.info('─────────────────────────────')
      log.info(`Operation: ${operationName}`)

      const hasAuthError = hasAuthenticationError(graphQLErrors)
      const rateLimitError = findRateLimitError(graphQLErrors)

      if (rateLimitError && onRateLimit) {
        onRateLimit(rateLimitError.retryAfter, rateLimitError.message)
        log.info('⏱️  Rate limit detected', rateLimitError)
      }

      graphQLErrors.forEach(({ message, path, extensions }, index) => {
        log.info(`Error ${index + 1}:`, { message, path, extensions })

        if (onGraphQLError) {
          onGraphQLError({
            message,
            path,
            extensions: extensions as Record<string, unknown>,
            operationName,
          })
        }
      })

      log.info('─────────────────────────────')

      if (hasAuthError) {
        return new Observable<FetchResult>((observer) => {
          handleAuthError(operationName, forward, operation)
            .then((result) => {
              if (result) {
                result.subscribe({
                  next: (value) => observer.next(value as FetchResult),
                  error: (err) => observer.error(err),
                  complete: () => observer.complete(),
                })
              } else {
                observer.complete()
              }
            })
            .catch((err) => observer.error(err))
        })
      }
    }

    if (networkError) {
      log.info('🌐 Network Error')
      log.info('─────────────────────────────')
      log.info(`Operation: ${operationName}`)
      log.error('Error:', networkError)

      if (onNetworkError) {
        onNetworkError(networkError, operationName)
      }

      if ('statusCode' in networkError && networkError.statusCode === AUTH_HTTP_STATUS.UNAUTHORIZED) {
        log.info('401 Unauthorized - attempting token refresh via machine')

        if (operationName === 'RefreshToken') {
          log.info('Refresh mutation failed with 401 - clearing session')
          onForceLogout()
          redirectToLogin()
          return
        }

        return new Observable<FetchResult>((observer) => {
          handleAuthError(operationName, forward, operation)
            .then((result) => {
              if (result) {
                result.subscribe({
                  next: (value) => observer.next(value as FetchResult),
                  error: (err) => observer.error(err),
                  complete: () => observer.complete(),
                })
              } else {
                observer.complete()
              }
            })
            .catch((err) => observer.error(err))
        })
      }

      log.info('─────────────────────────────')
    }
  }) as ErrorLink
}
