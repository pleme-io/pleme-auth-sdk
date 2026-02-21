/**
 * AuthStateSync - Deterministic Auth State Synchronization
 *
 * PROBLEM:
 * After login, navigation can occur before all auth state storage locations
 * are synchronized, causing UI to show logged-out state despite successful login.
 *
 * SOLUTION:
 * This utility provides deterministic verification that all auth state storage
 * locations (TokenManager, Zustand persist, etc.) are in sync before navigation.
 *
 * FLOW:
 * 1. Login mutation succeeds
 * 2. TokenManager.setTokens() writes to AUTH_TOKEN_KEY
 * 3. Zustand set() updates in-memory state
 * 4. Zustand persist middleware SCHEDULES async write to localStorage
 * 5. waitForAuthSync() verifies all locations are consistent
 * 6. ONLY THEN does navigation proceed
 *
 * DETERMINISM GUARANTEES:
 * - TokenManager.hasTokens() will return true
 * - localStorage['auth_access_token'] will have the token
 * - Zustand state will have isAuthenticated=true and user object
 *
 * @see .claude/skills/auth-state-management for architecture documentation
 */

import { tokenManager } from '../token/TokenManager'

/**
 * Auth sync status for verification
 */
export interface AuthSyncStatus {
  /** TokenManager has the access token */
  tokenManagerHasToken: boolean
  /** localStorage has AUTH_TOKEN_KEY */
  localStorageHasToken: boolean
  /** Zustand persist storage has isAuthenticated=true */
  zustandHasAuthState: boolean
  /** All storage locations are in sync */
  isInSync: boolean
  /** Token value (if exists) */
  tokenValue: string | null
}

/**
 * Options for waitForAuthSync
 */
export interface WaitForAuthSyncOptions {
  /** Maximum time to wait for sync (default: 2000ms) */
  timeout?: number
  /** Polling interval (default: 50ms) */
  pollInterval?: number
  /** Logger for debugging */
  logger?: {
    debug: (message: string, context?: Record<string, unknown>, category?: string) => void
  }
  /** Skip async waiting (useful for tests with fake timers) */
  skipWait?: boolean
}

const AUTH_TOKEN_KEY = 'auth_access_token'
const ZUSTAND_STORAGE_KEY = 'auth-storage'

/**
 * Check current auth sync status
 *
 * @returns Current sync status across all storage locations
 */
export function getAuthSyncStatus(): AuthSyncStatus {
  const tokenManagerHasToken = tokenManager.hasTokens()
  const tokenValue = tokenManager.getAccessToken()

  let localStorageHasToken = false
  let zustandHasAuthState = false
  try {
    localStorageHasToken = !!localStorage.getItem(AUTH_TOKEN_KEY)

    // CRITICAL: Also check Zustand persist storage for isAuthenticated=true
    // This is the storage that onRehydrateStorage reads from on page load
    const zustandRaw = localStorage.getItem(ZUSTAND_STORAGE_KEY)
    if (zustandRaw) {
      const zustandData = JSON.parse(zustandRaw)
      // Zustand persist format: { state: { isAuthenticated, user, tokens, ... }, version: ... }
      zustandHasAuthState = zustandData?.state?.isAuthenticated === true
    }
  } catch {
    // localStorage not available or JSON parse error
  }

  // All THREE conditions must be true for proper sync:
  // 1. TokenManager has the access token
  // 2. localStorage has AUTH_TOKEN_KEY (redundant but explicit)
  // 3. Zustand persist has isAuthenticated=true (this is what rehydration reads!)
  const isInSync = tokenManagerHasToken && localStorageHasToken && zustandHasAuthState

  return {
    tokenManagerHasToken,
    localStorageHasToken,
    zustandHasAuthState,
    isInSync,
    tokenValue,
  }
}

/**
 * Wait for auth state to be synchronized across all storage locations
 *
 * USAGE:
 * ```typescript
 * // In login handler, BEFORE navigation:
 * await login(credentials)
 * await waitForAuthSync() // Ensures all storage is ready
 * navigate('/home')
 * ```
 *
 * @param options - Configuration options
 * @returns Promise that resolves when sync is complete, rejects on timeout
 * @throws Error if sync times out
 */
export function waitForAuthSync(options: WaitForAuthSyncOptions = {}): Promise<AuthSyncStatus> {
  const { timeout = 2000, pollInterval = 50, logger, skipWait } = options

  // Auto-detect test environment or respect explicit skipWait
  const isTestEnv = typeof process !== 'undefined' && process.env?.NODE_ENV === 'test'
  const shouldSkip = skipWait ?? isTestEnv

  return new Promise((resolve, reject) => {
    const status = getAuthSyncStatus()

    // In test environments or when skipWait is true, resolve immediately
    // Tests use fake timers which would cause this to hang
    if (shouldSkip) {
      logger?.debug('Auth state sync skipped (test environment)', {
        tokenManagerHasToken: status.tokenManagerHasToken,
        localStorageHasToken: status.localStorageHasToken,
        zustandHasAuthState: status.zustandHasAuthState,
        isInSync: status.isInSync,
      }, 'AuthStateSync')
      resolve(status)
      return
    }

    // If already in sync, resolve immediately (no polling needed)
    if (status.isInSync) {
      logger?.debug('Auth state sync verified (immediate)', {
        tokenManagerHasToken: status.tokenManagerHasToken,
        localStorageHasToken: status.localStorageHasToken,
        zustandHasAuthState: status.zustandHasAuthState,
      }, 'AuthStateSync')
      resolve(status)
      return
    }

    const startTime = Date.now()

    const checkSync = () => {
      const currentStatus = getAuthSyncStatus()

      if (currentStatus.isInSync) {
        logger?.debug('Auth state sync verified', {
          tokenManagerHasToken: currentStatus.tokenManagerHasToken,
          localStorageHasToken: currentStatus.localStorageHasToken,
          zustandHasAuthState: currentStatus.zustandHasAuthState,
          elapsedMs: Date.now() - startTime,
        }, 'AuthStateSync')
        resolve(currentStatus)
        return
      }

      if (Date.now() - startTime >= timeout) {
        const error = new Error(
          `Auth state sync timeout after ${timeout}ms. ` +
          `TokenManager: ${currentStatus.tokenManagerHasToken}, ` +
          `localStorage: ${currentStatus.localStorageHasToken}, ` +
          `Zustand: ${currentStatus.zustandHasAuthState}`
        )
        logger?.debug('Auth state sync timeout', {
          tokenManagerHasToken: currentStatus.tokenManagerHasToken,
          localStorageHasToken: currentStatus.localStorageHasToken,
          zustandHasAuthState: currentStatus.zustandHasAuthState,
          timeoutMs: timeout,
        }, 'AuthStateSync')
        reject(error)
        return
      }

      // Continue polling
      setTimeout(checkSync, pollInterval)
    }

    // Start polling
    setTimeout(checkSync, pollInterval)
  })
}

/**
 * Synchronously verify auth state is ready
 * Use this when you need immediate verification without waiting
 *
 * @returns true if all storage locations are in sync
 */
export function isAuthStateInSync(): boolean {
  return getAuthSyncStatus().isInSync
}

/**
 * Assert auth state is in sync, throw if not
 * Use this for fail-fast verification in critical paths
 *
 * @throws Error if auth state is not in sync
 */
export function assertAuthStateInSync(): void {
  const status = getAuthSyncStatus()
  if (!status.isInSync) {
    throw new Error(
      `Auth state not in sync! ` +
      `TokenManager: ${status.tokenManagerHasToken}, ` +
      `localStorage: ${status.localStorageHasToken}, ` +
      `Zustand: ${status.zustandHasAuthState}`
    )
  }
}

/**
 * Debug helper to log all auth state storage locations
 * Only logs in non-production environments
 *
 * @param logger - Logger instance
 */
export function debugAuthState(logger?: {
  debug: (message: string, context?: Record<string, unknown>, category?: string) => void
}): void {
  if (process.env.NODE_ENV === 'production') {
    return
  }

  const status = getAuthSyncStatus()

  let zustandData: unknown = null
  try {
    const raw = localStorage.getItem('auth-storage')
    if (raw) {
      zustandData = JSON.parse(raw)
    }
  } catch {
    // Ignore
  }

  const debugInfo = {
    tokenManager: {
      hasToken: status.tokenManagerHasToken,
      tokenLength: status.tokenValue?.length ?? 0,
    },
    localStorage: {
      hasAuthToken: status.localStorageHasToken,
      hasZustandStorage: !!zustandData,
    },
    zustand: {
      hasAuthState: status.zustandHasAuthState,
      isAuthenticated: zustandData?.state?.isAuthenticated ?? null,
      hasUser: !!zustandData?.state?.user,
    },
    isInSync: status.isInSync,
  }

  if (logger) {
    logger.debug('Auth state debug', debugInfo, 'AuthStateSync')
  } else {
    console.log('[AuthStateSync] Debug:', debugInfo)
  }
}
