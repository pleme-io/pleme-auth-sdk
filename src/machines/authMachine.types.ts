/**
 * XState Auth Machine Types
 *
 * Type definitions for the authentication state machine.
 * Uses XState v5 typegen-free approach with explicit typing.
 */

import type { ApolloClient, NormalizedCacheObject } from '@apollo/client'
import type { AuthTokens, AuthUser, LoginCredentials, SignupData } from '@pleme/types'

/**
 * Logger interface for auth machine
 */
export interface AuthLogger {
  info: (message: string, context?: Record<string, unknown>, category?: string) => void
  warn: (message: string, context?: Record<string, unknown>, category?: string) => void
  error: (message: string, context?: Record<string, unknown>, category?: string) => void
  debug: (message: string, context?: Record<string, unknown>, category?: string) => void
}

/**
 * Auth machine context - the extended state
 *
 * WORLD-CLASS SESSION HANDLING:
 * This context tracks all necessary state for enterprise-grade session management:
 * - Absolute timeout tracking (sessionStartedAt)
 * - Idle timeout tracking (lastActivityAt)
 * - Session metadata for security auditing
 */
export interface AuthContext {
  /** Current authenticated user */
  user: AuthUser | null
  /** Current tokens (access token stored in memory, refresh in HttpOnly cookie) */
  tokens: AuthTokens | null
  /** Last error that occurred */
  error: AuthError | null
  /** Number of consecutive refresh attempts */
  refreshAttempts: number
  /** Timestamp of last successful authentication */
  lastAuthenticatedAt: number | null
  /**
   * ABSOLUTE TIMEOUT: When the current session started
   * Used to enforce maximum session duration (e.g., 24 hours)
   * regardless of user activity or token refresh
   */
  sessionStartedAt: number | null
  /**
   * IDLE TIMEOUT: Last user activity timestamp
   * Updated on user interactions (mouse, keyboard, scroll)
   * Used to log out inactive users (e.g., 30 minutes)
   */
  lastActivityAt: number | null
}

/**
 * Auth error structure
 */
export interface AuthError {
  message: string
  code: AuthErrorCode
  originalError?: unknown
}

/**
 * Error codes for auth operations
 */
export type AuthErrorCode =
  | 'INVALID_CREDENTIALS'
  | 'NETWORK_ERROR'
  | 'TOKEN_EXPIRED'
  | 'TOKEN_INVALID'
  | 'REFRESH_FAILED'
  | 'SESSION_EXPIRED'
  | 'UNAUTHORIZED'
  | 'VALIDATION_ERROR'
  | 'UNKNOWN'

/**
 * Registration result
 */
export interface RegisterResult {
  verificationRequired: boolean
  message: string
  userId: string
  email: string
}

/**
 * Auth machine events
 */
export type AuthEvent =
  | { type: 'LOGIN'; credentials: LoginCredentials }
  | { type: 'REGISTER'; data: SignupData }
  | { type: 'LOGOUT' }
  | { type: 'FORCE_LOGOUT' }
  | { type: 'CHECK_AUTH' }
  | { type: 'REFRESH_TOKEN' }
  | { type: 'TOKEN_EXPIRING' }
  | { type: 'SET_AUTH'; user: AuthUser; tokens: AuthTokens }
  | { type: 'CLEAR_ERROR' }
  // Apollo integration event - Apollo error link reports auth errors here
  // Machine decides whether to refresh, logout, or ignore
  | { type: 'APOLLO_AUTH_ERROR'; operation?: string }
  // Session timeout events (world-class session handling)
  | { type: 'USER_ACTIVITY' } // User interaction detected - reset idle timer
  | { type: 'IDLE_WARNING' } // About to be logged out due to inactivity
  | { type: 'IDLE_TIMEOUT' } // Session expired due to inactivity
  | { type: 'ABSOLUTE_TIMEOUT' } // Session expired due to max duration
  | { type: 'EXTEND_SESSION' } // User chose to extend session (dismiss idle warning)
  // Internal events (from invoked services)
  | { type: 'xstate.done.actor.loginService'; output: LoginOutput }
  | { type: 'xstate.error.actor.loginService'; error: unknown }
  | { type: 'xstate.done.actor.registerService'; output: RegisterResult }
  | { type: 'xstate.error.actor.registerService'; error: unknown }
  | { type: 'xstate.done.actor.logoutService'; output: void }
  | { type: 'xstate.error.actor.logoutService'; error: unknown }
  | { type: 'xstate.done.actor.refreshService'; output: RefreshOutput }
  | { type: 'xstate.error.actor.refreshService'; error: unknown }
  | { type: 'xstate.done.actor.checkAuthService'; output: CheckAuthOutput }
  | { type: 'xstate.error.actor.checkAuthService'; error: unknown }

/**
 * Output from login service
 */
export interface LoginOutput {
  user: AuthUser
  tokens: AuthTokens
}

/**
 * Output from refresh service
 */
export interface RefreshOutput {
  tokens: AuthTokens
}

/**
 * Output from check auth service
 */
export interface CheckAuthOutput {
  user: AuthUser | null
}

/**
 * Session configuration for world-class session handling
 *
 * These settings allow fine-tuning session behavior based on
 * security requirements vs. user experience trade-offs.
 */
export interface SessionConfig {
  /**
   * ABSOLUTE TIMEOUT: Maximum session duration in milliseconds
   * Session will expire regardless of user activity after this duration
   * Default: 24 hours (86400000ms)
   * Recommended: 4-24 hours depending on security requirements
   */
  absoluteTimeoutMs: number
  /**
   * IDLE TIMEOUT: Inactivity timeout in milliseconds
   * Session expires if no user activity within this duration
   * Default: 30 minutes (1800000ms)
   * Set to 0 to disable idle timeout
   */
  idleTimeoutMs: number
  /**
   * IDLE WARNING: Show warning before idle logout in milliseconds
   * User gets a chance to extend session before forced logout
   * Default: 5 minutes (300000ms)
   */
  idleWarningMs: number
  /**
   * TOKEN REFRESH BUFFER: Refresh token before expiry in seconds
   * Prevents edge cases where token expires during request
   * Default: 60 seconds
   */
  refreshBufferSeconds: number
  /**
   * MAX REFRESH ATTEMPTS: How many times to retry failed refresh
   * After max attempts, user is logged out
   * Default: 3
   */
  maxRefreshAttempts: number
}

/**
 * Default session configuration - balanced security/UX
 */
export const DEFAULT_SESSION_CONFIG: SessionConfig = {
  absoluteTimeoutMs: 24 * 60 * 60 * 1000, // 24 hours
  idleTimeoutMs: 30 * 60 * 1000, // 30 minutes
  idleWarningMs: 5 * 60 * 1000, // 5 minutes warning
  refreshBufferSeconds: 60,
  maxRefreshAttempts: 3,
}

/**
 * Machine input (dependencies)
 */
export interface AuthMachineInput {
  apolloClient: ApolloClient<NormalizedCacheObject>
  logger?: AuthLogger
  /** Initial tokens restored from localStorage (for session persistence) */
  initialTokens?: AuthTokens | null
  /** Initial user restored from localStorage (for session persistence) */
  initialUser?: AuthUser | null
  /**
   * Skip initial auth check (checkAuth) on machine start
   *
   * When TRUE: Machine starts in 'authenticated' state directly
   * When FALSE: Machine goes through 'initializing' -> 'checkingAuth' flow
   *
   * This should be TRUE when we have valid (non-expired) tokens AND user
   * restored from localStorage. This prevents unnecessary network requests
   * and ensures instant authentication state on page reload.
   */
  skipInitialCheck?: boolean
  /**
   * Session start timestamp for restored sessions
   * Used to calculate absolute timeout on page reload
   */
  sessionStartedAt?: number | null
  /**
   * Session configuration for timeouts and limits
   * Uses DEFAULT_SESSION_CONFIG if not provided
   */
  sessionConfig?: Partial<SessionConfig>
}

/**
 * Auth machine state values
 */
export type AuthStateValue =
  | 'initializing'
  | 'idle'
  | 'checkingAuth'
  | 'loggingIn'
  | 'registering'
  | 'authenticated'
  | 'refreshingToken'
  | 'loggingOut'
  | 'error'

/**
 * Type guard helpers
 */
export function isAuthError(error: unknown): error is AuthError {
  return (
    typeof error === 'object' &&
    error !== null &&
    'message' in error &&
    'code' in error
  )
}

/**
 * Create an AuthError from unknown error
 */
export function createAuthError(
  error: unknown,
  defaultCode: AuthErrorCode = 'UNKNOWN'
): AuthError {
  if (isAuthError(error)) {
    return error
  }

  const message =
    error instanceof Error
      ? error.message
      : typeof error === 'string'
        ? error
        : 'An unknown error occurred'

  return {
    message,
    code: defaultCode,
    originalError: error,
  }
}
