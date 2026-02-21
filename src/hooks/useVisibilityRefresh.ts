/**
 * useVisibilityRefresh - Automatic token refresh when app becomes visible
 *
 * This hook handles token refresh when the user returns to the app after
 * being away (tab switching, app backgrounding, etc.). This is critical
 * because timers can be lost or delayed when the app is backgrounded.
 *
 * PROBLEM SOLVED:
 * - Users get logged out when returning to the app after some time
 * - Timers don't fire reliably when app is backgrounded
 * - Network delays can cause scheduled refreshes to miss their window
 *
 * STRATEGY:
 * - Check token expiry when visibility changes to 'visible'
 * - Refresh proactively if token is close to expiry (< threshold)
 * - Refresh immediately if token is already expired
 * - Uses RefreshCoordinator to prevent race conditions with other refresh sources
 */

import { useEffect } from 'react'
import { isTokenExpired, getSecondsUntilExpiry } from '../utils/jwt'
import { refreshCoordinator } from '../refresh'
import { logger } from '../utils/logger'

/**
 * Configuration for the visibility refresh hook
 */
export interface UseVisibilityRefreshConfig {
  /**
   * Function to get the current access token
   * Should return null if not authenticated
   */
  getAccessToken: () => string | null

  /**
   * Whether the user is currently authenticated
   * Hook is disabled when false
   */
  isAuthenticated: boolean

  /**
   * Threshold in seconds before expiry to trigger proactive refresh
   * @default 900 (15 minutes)
   */
  refreshThresholdSeconds?: number

  /**
   * Optional callback when refresh is triggered
   */
  onRefreshTriggered?: (reason: 'expired' | 'proactive') => void

  /**
   * Optional callback when refresh completes
   */
  onRefreshComplete?: (success: boolean, error?: Error) => void

  /**
   * Whether to enable logging
   * @default true in development
   */
  enableLogging?: boolean
}

/**
 * React hook for automatic token refresh on visibility change
 *
 * @param config - Configuration for the hook
 *
 * @example
 * ```typescript
 * import { useVisibilityRefresh } from '@pleme/auth-sdk'
 * import { useAuthStore } from './auth.store'
 *
 * function AuthProvider({ children }) {
 *   const { tokens, isAuthenticated } = useAuthStore()
 *
 *   useVisibilityRefresh({
 *     getAccessToken: () => tokens?.accessToken ?? null,
 *     isAuthenticated,
 *     refreshThresholdSeconds: 900, // 15 minutes
 *     onRefreshComplete: (success) => {
 *       if (!success) {
 *         // Handle refresh failure
 *       }
 *     },
 *   })
 *
 *   return children
 * }
 * ```
 */
export function useVisibilityRefresh(config: UseVisibilityRefreshConfig): void {
  const {
    getAccessToken,
    isAuthenticated,
    refreshThresholdSeconds = 900, // 15 minutes
    onRefreshTriggered,
    onRefreshComplete,
    enableLogging = process.env.NODE_ENV !== 'production',
  } = config

  useEffect(() => {
    if (!isAuthenticated) {
      return
    }

    const handleVisibilityChange = async () => {
      // Only act when becoming visible
      if (document.visibilityState !== 'visible') {
        return
      }

      const accessToken = getAccessToken()
      if (!accessToken) {
        return
      }

      // Check if token is expired
      if (isTokenExpired(accessToken)) {
        if (enableLogging) {
          logger.warn('Token expired while app was hidden - refreshing via coordinator', {}, 'Auth')
        }
        onRefreshTriggered?.('expired')

        const result = await refreshCoordinator.refresh()

        if (enableLogging) {
          if (result.success) {
            logger.info('Token successfully refreshed on visibility change', {}, 'Auth')
          } else {
            logger.error('Failed to refresh expired token on visibility change', { error: result.error }, 'Auth')
          }
        }

        onRefreshComplete?.(result.success, result.error)
        return
      }

      // Check if token is close to expiry
      const secondsUntilExpiry = getSecondsUntilExpiry(accessToken)
      if (secondsUntilExpiry === null) {
        return
      }

      if (secondsUntilExpiry < refreshThresholdSeconds) {
        if (enableLogging) {
          logger.info(
            'Token close to expiry on visibility change - refreshing proactively via coordinator',
            {
              secondsUntilExpiry,
              threshold: refreshThresholdSeconds,
            },
            'Auth'
          )
        }
        onRefreshTriggered?.('proactive')

        const result = await refreshCoordinator.refresh()

        if (enableLogging) {
          if (result.success) {
            logger.info('Token successfully refreshed proactively on visibility change', {}, 'Auth')
          } else {
            logger.error('Failed to refresh token proactively on visibility change', { error: result.error }, 'Auth')
          }
        }

        onRefreshComplete?.(result.success, result.error)
      }
    }

    document.addEventListener('visibilitychange', handleVisibilityChange)

    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange)
    }
  }, [isAuthenticated, getAccessToken, refreshThresholdSeconds, onRefreshTriggered, onRefreshComplete, enableLogging])
}
