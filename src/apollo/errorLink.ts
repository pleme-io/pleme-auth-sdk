/**
 * Apollo Error Link Factory
 *
 * Creates an Apollo Link that handles authentication errors with proper
 * Zanzibar-compliant distinction between AuthN and AuthZ errors.
 *
 * CRITICAL DISTINCTION:
 * - UNAUTHENTICATED: "I don't know who you are" → trigger token refresh
 * - FORBIDDEN: "I know who you are, but you can't do this" → show error, do NOT refresh
 */

import { onError, ErrorResponse, type ErrorLink } from '@apollo/client/link/error'
import { Observable, FetchResult } from '@apollo/client'
import { AUTH_ERROR_CODES, AUTH_HTTP_STATUS } from './constants'
import { refreshCoordinator, type RefreshResult } from '../refresh'

/**
 * Configuration for creating an error link
 */
export interface ErrorLinkConfig {
  /**
   * Function to call when user should be logged out
   * Called when refresh fails or RefreshToken mutation itself fails
   */
  onForceLogout: () => void

  /**
   * Function to get the redirect URL for login
   * Should preserve the current path for redirect after login
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
 *
 * IMPORTANT: FORBIDDEN is NOT an auth error - it means user IS authenticated
 * but lacks permission. Only UNAUTHENTICATED should trigger refresh.
 */
function hasAuthenticationError(errors: readonly { extensions?: { code?: unknown } }[]): boolean {
  return errors.some((error) => {
    const code = error.extensions?.code
    // ONLY UNAUTHENTICATED triggers refresh, NOT FORBIDDEN
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
 * Create an Apollo Error Link with proper authentication error handling
 *
 * FEATURES:
 * - Distinguishes UNAUTHENTICATED (refresh token) from FORBIDDEN (show error)
 * - Uses RefreshCoordinator for race-condition-proof token refresh
 * - Preserves current URL when redirecting to login
 * - Handles rate limiting
 * - Handles network 401 errors
 *
 * @param config - Configuration for the error link
 * @returns Apollo Link for error handling
 *
 * @example
 * ```typescript
 * import { createErrorLink } from '@pleme/auth-sdk'
 *
 * const errorLink = createErrorLink({
 *   onForceLogout: () => {
 *     useAuthStore.getState().forceLogout()
 *   },
 *   getLoginRedirectUrl: () => {
 *     const currentPath = window.location.pathname + window.location.search
 *     return `/login?redirect=${encodeURIComponent(currentPath)}`
 *   },
 *   onRateLimit: (retryAfter, message) => {
 *     useRateLimitStore.getState().setRateLimit(retryAfter, message)
 *   },
 * })
 * ```
 */
export function createErrorLink(config: ErrorLinkConfig): ErrorLink {
  const {
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

  /**
   * Redirect to login with current URL preserved
   */
  const redirectToLogin = () => {
    window.location.href = getLoginRedirectUrl()
  }

  /**
   * Handle authentication error by attempting token refresh
   */
  const handleAuthError = async (
    operationName: string | undefined,
    forward: ErrorResponse['forward'],
    operation: ErrorResponse['operation']
  ): Promise<Observable<unknown> | void> => {
    log.info('⚠️  Authentication error detected - attempting token refresh')

    // Don't try to refresh if this IS the refresh mutation (would cause infinite loop)
    if (operationName === 'RefreshToken') {
      log.info('Refresh mutation itself failed - clearing session')
      onForceLogout()
      redirectToLogin()
      return
    }

    // Use RefreshCoordinator to handle token refresh
    // This is race-condition-proof: all callers share the same refresh promise
    const result: RefreshResult = await refreshCoordinator.refresh()

    if (result.success) {
      log.info('Retrying operation after token refresh:', operationName)
      // Token refreshed successfully - retry the operation
      return forward(operation)
    } else {
      // Refresh failed - clear session and redirect (preserving current URL)
      log.info('Token refresh failed - clearing session', result.error?.message)
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

      // Check for authentication errors (UNAUTHENTICATED only, NOT FORBIDDEN)
      const hasAuthError = hasAuthenticationError(graphQLErrors)

      // Check for rate limit errors
      const rateLimitError = findRateLimitError(graphQLErrors)
      if (rateLimitError && onRateLimit) {
        onRateLimit(rateLimitError.retryAfter, rateLimitError.message)
        log.info('⏱️  Rate limit detected', rateLimitError)
      }

      // Log and report each error
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

      // Handle authentication errors - try to refresh token first
      if (hasAuthError) {
        // Return the promise as an Observable
        return new Observable<FetchResult>((observer) => {
          handleAuthError(operationName, forward, operation)
            .then((result) => {
              if (result) {
                // If we got an observable back (from forward), subscribe to it
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

      // Handle 401 network errors - try token refresh
      if ('statusCode' in networkError && networkError.statusCode === AUTH_HTTP_STATUS.UNAUTHORIZED) {
        log.info('401 Unauthorized - attempting token refresh')

        // Don't try to refresh if this IS the refresh mutation
        if (operationName === 'RefreshToken') {
          log.info('Refresh mutation failed with 401 - clearing session')
          onForceLogout()
          redirectToLogin()
          return
        }

        // Return the promise as an Observable
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
  })
}
