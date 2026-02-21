/**
 * RefreshCoordinator - Centralized Token Refresh Management
 *
 * ARCHITECTURAL DECISION:
 * This singleton coordinates ALL token refresh attempts across the application:
 * - Apollo Client error link (HTTP auth failures)
 * - WebSocket reconnections
 * - Scheduled background refresh
 * - Visibility-based refresh (tab focus)
 * - Rehydration refresh
 *
 * GUARANTEES:
 * 1. Only ONE refresh operation can run at a time (race-condition-proof)
 * 2. Concurrent callers get the same promise (wait for in-progress refresh)
 * 3. Refresh failures are propagated to all waiters
 * 4. Success/failure state is tracked for debugging
 *
 * USAGE:
 * ```typescript
 * import { refreshCoordinator } from '@pleme/auth-sdk'
 *
 * // Register the refresh callback during app initialization
 * refreshCoordinator.registerRefreshCallback(async () => {
 *   await authStore.refreshToken()
 * })
 *
 * // Use in error handlers, visibility changes, etc.
 * const { success, error } = await refreshCoordinator.refresh()
 * if (success) {
 *   // Token refreshed - retry operation
 * } else {
 *   // Refresh failed - redirect to login
 * }
 * ```
 */

/**
 * Result of a refresh operation
 */
export interface RefreshResult {
  /** Whether the refresh was successful */
  success: boolean
  /** Error if refresh failed */
  error?: Error
  /** Timestamp when refresh completed */
  retriedAt?: number
}

/**
 * Statistics for monitoring refresh behavior
 */
export interface RefreshStats {
  /** Total refresh attempts */
  totalAttempts: number
  /** Number of successful refreshes */
  successfulRefreshes: number
  /** Number of failed refreshes */
  failedRefreshes: number
  /** Timestamp of last successful refresh */
  lastRefreshAt: number | null
  /** Last error encountered */
  lastError: Error | null
  /** Whether a refresh is currently in progress */
  isRefreshing: boolean
}

/**
 * Callback type for the actual refresh implementation
 * This is injected to avoid circular dependencies with the auth store
 */
export type RefreshCallback = () => Promise<void>

/**
 * Logger interface for flexibility
 */
interface Logger {
  info: (message: string, context?: Record<string, unknown>, category?: string) => void
  warn: (message: string, context?: Record<string, unknown>, category?: string) => void
  error: (message: string, context?: Record<string, unknown>, category?: string) => void
  debug: (message: string, context?: Record<string, unknown>, category?: string) => void
}

/**
 * Default console logger
 */
const defaultLogger: Logger = {
  info: (message, context) => console.log(`[RefreshCoordinator] ${message}`, context || ''),
  warn: (message, context) => console.warn(`[RefreshCoordinator] ${message}`, context || ''),
  error: (message, context) => console.error(`[RefreshCoordinator] ${message}`, context || ''),
  debug: (message, context) => console.debug(`[RefreshCoordinator] ${message}`, context || ''),
}

/**
 * RefreshCoordinator implementation
 * Singleton pattern ensures only one coordinator exists
 */
class RefreshCoordinatorImpl {
  private static instance: RefreshCoordinatorImpl
  private refreshPromise: Promise<RefreshResult> | null = null
  private refreshCallback: RefreshCallback | null = null
  private logger: Logger = defaultLogger
  private stats: RefreshStats = {
    totalAttempts: 0,
    successfulRefreshes: 0,
    failedRefreshes: 0,
    lastRefreshAt: null,
    lastError: null,
    isRefreshing: false,
  }

  private constructor() {
    // Private constructor for singleton pattern
  }

  /**
   * Get singleton instance
   */
  public static getInstance(): RefreshCoordinatorImpl {
    if (!RefreshCoordinatorImpl.instance) {
      RefreshCoordinatorImpl.instance = new RefreshCoordinatorImpl()
    }
    return RefreshCoordinatorImpl.instance
  }

  /**
   * Configure the coordinator with a custom logger
   *
   * @param logger - Logger implementation to use
   */
  public setLogger(logger: Logger): void {
    this.logger = logger
  }

  /**
   * Register the refresh callback
   * MUST be called during app initialization before any refresh attempts
   *
   * @param callback - Function that performs the actual token refresh
   */
  public registerRefreshCallback(callback: RefreshCallback): void {
    this.refreshCallback = callback
    this.logger.info('Refresh callback registered')
  }

  /**
   * Check if a refresh is currently in progress
   */
  public isRefreshing(): boolean {
    return this.stats.isRefreshing
  }

  /**
   * Get refresh statistics for debugging/monitoring
   */
  public getStats(): RefreshStats {
    return { ...this.stats }
  }

  /**
   * Attempt to refresh the token
   *
   * RACE-CONDITION-PROOF:
   * - If a refresh is already in progress, returns the same promise
   * - All concurrent callers will receive the same result
   * - Only one actual refresh request is made
   *
   * @returns Promise resolving to RefreshResult
   */
  public async refresh(): Promise<RefreshResult> {
    // If refresh is already in progress, return the existing promise
    // This is the KEY to preventing race conditions
    if (this.refreshPromise) {
      this.logger.debug('Refresh already in progress - waiting for existing promise')
      return this.refreshPromise
    }

    // Ensure callback is registered
    if (!this.refreshCallback) {
      const error = new Error('Refresh callback not registered')
      this.logger.error('Cannot refresh - callback not registered')
      return { success: false, error }
    }

    // Start new refresh operation
    this.logger.info('Starting token refresh', { totalAttempts: this.stats.totalAttempts + 1 })
    this.stats.totalAttempts++
    this.stats.isRefreshing = true

    // Create and store the refresh promise
    this.refreshPromise = this.executeRefresh()

    try {
      const result = await this.refreshPromise
      return result
    } finally {
      // Clear the promise to allow future refreshes
      this.refreshPromise = null
      this.stats.isRefreshing = false
    }
  }

  /**
   * Execute the actual refresh operation
   * Separated from refresh() for cleaner promise handling
   */
  private async executeRefresh(): Promise<RefreshResult> {
    try {
      await this.refreshCallback!()

      // Success
      this.stats.successfulRefreshes++
      this.stats.lastRefreshAt = Date.now()
      this.stats.lastError = null

      this.logger.info('Token refresh successful', {
        totalSuccesses: this.stats.successfulRefreshes,
      })

      return { success: true, retriedAt: Date.now() }
    } catch (error) {
      // Failure
      this.stats.failedRefreshes++
      this.stats.lastError = error instanceof Error ? error : new Error(String(error))

      this.logger.error('Token refresh failed', {
        error: this.stats.lastError.message,
        totalFailures: this.stats.failedRefreshes,
      })

      return {
        success: false,
        error: this.stats.lastError,
      }
    }
  }

  /**
   * Reset statistics (useful for testing)
   */
  public resetStats(): void {
    this.stats = {
      totalAttempts: 0,
      successfulRefreshes: 0,
      failedRefreshes: 0,
      lastRefreshAt: null,
      lastError: null,
      isRefreshing: false,
    }
  }

  /**
   * Wait for any in-progress refresh to complete
   * Useful for operations that need fresh tokens
   */
  public async waitForRefresh(): Promise<RefreshResult | null> {
    if (!this.refreshPromise) {
      return null
    }
    return this.refreshPromise
  }

  /**
   * Reset the singleton instance (for testing only)
   * @internal
   */
  public static resetInstance(): void {
    RefreshCoordinatorImpl.instance = null as unknown as RefreshCoordinatorImpl
  }
}

/**
 * Singleton instance of RefreshCoordinator
 * Import this for use throughout your application
 */
export const refreshCoordinator: RefreshCoordinatorImpl = RefreshCoordinatorImpl.getInstance()

/**
 * Export the class for testing purposes
 * @internal
 */
export { RefreshCoordinatorImpl }
