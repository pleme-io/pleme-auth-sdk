/**
 * Auth Handlers Registry
 *
 * @deprecated December 2025 - This pattern is DEPRECATED.
 *
 * PROBLEM: This registry creates a second source of truth that races with XState.
 * Apollo error link could call handlers before/after machine state transitions,
 * causing the "login then immediate logout" bug.
 *
 * NEW PATTERN: Apollo sends events directly to the Zustand store:
 *   store.sendEvent({ type: 'APOLLO_AUTH_ERROR' })
 *
 * The XState machine then decides whether to refresh, logout, or ignore.
 * See .claude/skills/authentication-session-architecture.md for the new pattern.
 *
 * This file is kept for legacy authStore.ts compatibility but should NOT
 * be used by new code. Use createAuthMachineStore + sendEvent instead.
 */

/**
 * Handlers that can be registered by the auth system
 */
export interface AuthHandlers {
  /**
   * Called when a token refresh is needed (e.g., 401 error)
   * Should return true if refresh succeeded, false otherwise
   */
  onRefreshNeeded: () => Promise<boolean>

  /**
   * Called when the user should be logged out (e.g., refresh failed)
   */
  onForceLogout: () => void

  /**
   * Called to clear the access token (for immediate effect)
   */
  onClearToken?: () => void
}

// Registered handlers (null until auth system initializes)
let registeredHandlers: AuthHandlers | null = null

/**
 * Register auth handlers
 * Called by useAuthMachine when it initializes
 */
export function registerAuthHandlers(handlers: AuthHandlers): void {
  registeredHandlers = handlers
}

/**
 * Unregister auth handlers
 * Called when auth system unmounts
 */
export function unregisterAuthHandlers(): void {
  registeredHandlers = null
}

/**
 * Check if handlers are registered
 */
export function hasAuthHandlers(): boolean {
  return registeredHandlers !== null
}

/**
 * Attempt to refresh the token
 * Called by error link when auth error detected
 *
 * @returns Promise<boolean> - true if refresh succeeded
 */
export async function attemptRefresh(): Promise<boolean> {
  if (!registeredHandlers) {
    console.warn('[Auth] No auth handlers registered - cannot refresh token')
    return false
  }

  try {
    return await registeredHandlers.onRefreshNeeded()
  } catch (error) {
    console.error('[Auth] Refresh handler threw error:', error)
    return false
  }
}

/**
 * Force logout the user
 * Called by error link when refresh fails
 */
export function forceLogout(): void {
  if (!registeredHandlers) {
    console.warn('[Auth] No auth handlers registered - cannot force logout')
    return
  }

  try {
    registeredHandlers.onForceLogout()
  } catch (error) {
    console.error('[Auth] Force logout handler threw error:', error)
  }
}

/**
 * Clear the access token immediately
 * Used for synchronous token clearing without waiting for machine
 */
export function clearToken(): void {
  if (registeredHandlers?.onClearToken) {
    registeredHandlers.onClearToken()
  }
}
