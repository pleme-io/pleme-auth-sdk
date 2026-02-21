/**
 * XState + Zustand Unified Auth Store
 *
 * ARCHITECTURE:
 * - XState machine is the COORDINATOR: owns all state transition logic
 * - Zustand store is the ADAPTER: derives state from machine for React
 *
 * WHY THIS PATTERN:
 * 1. Single source of truth: XState machine context
 * 2. Deterministic: State transitions are explicit and visualizable
 * 3. No flicker: isLoading vs isRefreshing properly separated via nested states
 * 4. Testable: Machine is pure, transitions can be tested directly
 * 5. Traceable: XState DevTools show exact state history
 *
 * STATE DERIVATION:
 * - isAuthenticated = machine.matches('authenticated')
 * - isLoading = machine.matches('loggingIn') || machine.matches('loggingOut') || ...
 * - isRefreshing = machine.matches({ authenticated: 'refreshingToken' })
 *
 * The key insight is that refreshingToken is a NESTED state under authenticated,
 * so isAuthenticated remains TRUE during background refresh (no UI flicker).
 */

import { create, type UseBoundStore, type StoreApi } from 'zustand'
import { createActor, type AnyActorRef, type Snapshot } from 'xstate'
import type { ApolloClient, NormalizedCacheObject } from '@apollo/client'
import type { AuthTokens, AuthUser, LoginCredentials, SignupData, RegisterResult } from '@pleme/types'
import { AppError } from '@pleme/types'
import { createAuthMachine, registerTokenProvider, setAccessToken, type AuthMachine } from '../machines/authMachine'
import type { AuthContext, AuthEvent } from '../machines/authMachine.types'
import { AUTH_TOKEN_KEY, ZUSTAND_STORAGE_KEY } from '../token/constants'
import { isTokenExpired } from '../utils/jwt'

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
  info: (message, context, category) =>
    console.log(`[${category || 'AuthMachine'}] ${message}`, context || ''),
  warn: (message, context, category) =>
    console.warn(`[${category || 'AuthMachine'}] ${message}`, context || ''),
  error: (message, context, category) =>
    console.error(`[${category || 'AuthMachine'}] ${message}`, context || ''),
  debug: (message, context, category) =>
    console.debug(`[${category || 'AuthMachine'}] ${message}`, context || ''),
}

/**
 * Restored session data from localStorage
 */
interface RestoredSession {
  tokens: AuthTokens | null
  user: AuthUser | null
  /** Whether the access token is still valid (not expired) */
  tokenValid: boolean
  /** WORLD-CLASS: When the session was originally started (for absolute timeout) */
  sessionStartedAt: number | null
}

/**
 * Restore session from localStorage on page reload
 *
 * CRITICAL FOR SESSION PERSISTENCE:
 * On page reload, the XState machine starts fresh with no state.
 * This function reads BOTH tokens AND user from localStorage so the machine
 * can restore the authenticated state immediately without network requests.
 *
 * Storage locations:
 * - AUTH_TOKEN_KEY ('auth_access_token'): Simple access token for Apollo Client
 * - ZUSTAND_STORAGE_KEY ('auth-storage'): Full auth state with tokens and user
 *
 * OPTIMIZATION: If we have valid (non-expired) tokens AND user data,
 * we can skip the initial checkAuth and start in authenticated state directly.
 */
function restoreSessionFromStorage(logger: Logger): RestoredSession {
  const emptySession: RestoredSession = { tokens: null, user: null, tokenValid: false, sessionStartedAt: null }

  if (typeof window === 'undefined' || !window.localStorage) {
    return emptySession
  }

  try {
    // First, try to restore from Zustand storage (most complete - has both tokens AND user)
    const zustandData = localStorage.getItem(ZUSTAND_STORAGE_KEY)
    if (zustandData) {
      const parsed = JSON.parse(zustandData)
      const tokens = parsed.state?.tokens as AuthTokens | undefined
      const user = parsed.state?.user as AuthUser | undefined
      // WORLD-CLASS: Restore session start time for absolute timeout tracking
      const sessionStartedAt = parsed.state?.sessionStartedAt as number | undefined

      if (tokens?.accessToken) {
        // Check if the token is still valid (not expired)
        // Use a 5-second buffer - just enough to avoid edge cases without being too aggressive
        // CRITICAL: 30 seconds was too aggressive and caused valid tokens to appear expired
        // during page reload, leading to the "login then immediate logout" bug
        const tokenValid = !isTokenExpired(tokens.accessToken, 5)

        logger.info('Restored session from Zustand storage', {
          hasAccessToken: true,
          hasRefreshToken: !!tokens.refreshToken,
          hasUser: !!user,
          tokenValid,
          sessionStartedAt,
        }, 'AuthMachine')

        return {
          tokens,
          user: user ?? null,
          tokenValid,
          sessionStartedAt: sessionStartedAt ?? null,
        }
      }
    }

    // Fallback: try AUTH_TOKEN_KEY (might be out of sync, but better than nothing)
    // Note: This path doesn't have user data, so we can't skip checkAuth
    const accessToken = localStorage.getItem(AUTH_TOKEN_KEY)
    if (accessToken) {
      // Use 5-second buffer (same as main path) to avoid false expiry detection
      const tokenValid = !isTokenExpired(accessToken, 5)

      logger.info('Restored access token from AUTH_TOKEN_KEY (no user data)', {
        tokenValid,
      }, 'AuthMachine')

      return {
        tokens: {
          accessToken,
          refreshToken: '', // Will be refreshed via HttpOnly cookie
          expiresIn: 3600, // Default, will be updated on refresh
          tokenType: 'Bearer',
        },
        user: null, // Can't skip checkAuth without user
        tokenValid,
        sessionStartedAt: null, // Unknown without full state
      }
    }

    return emptySession
  } catch (error) {
    logger.warn('Failed to restore session from storage', {
      error: error instanceof Error ? error.message : String(error),
    }, 'AuthMachine')
    return emptySession
  }
}

/**
 * Persist session to localStorage for session persistence across page reloads
 *
 * WORLD-CLASS SESSION HANDLING:
 * Now persists session start time for absolute timeout tracking across reloads
 *
 * Stores to both:
 * - AUTH_TOKEN_KEY: For Apollo Client
 * - ZUSTAND_STORAGE_KEY: For full state restoration (including session metadata)
 */
function persistSessionToStorage(
  tokens: AuthTokens | null,
  user: AuthUser | null,
  sessionStartedAt: number | null,
  logger: Logger
): void {
  if (typeof window === 'undefined' || !window.localStorage) {
    return
  }

  try {
    if (tokens?.accessToken) {
      // Store access token for Apollo Client
      localStorage.setItem(AUTH_TOKEN_KEY, tokens.accessToken)

      // Store full state in Zustand storage format (including session metadata)
      const zustandState = {
        state: {
          tokens,
          user,
          // WORLD-CLASS: Persist session start time for absolute timeout
          sessionStartedAt,
        },
        version: 0,
      }
      localStorage.setItem(ZUSTAND_STORAGE_KEY, JSON.stringify(zustandState))

      logger.debug('Persisted session to storage', {
        hasAccessToken: true,
        hasRefreshToken: !!tokens.refreshToken,
        sessionStartedAt,
      }, 'AuthMachine')
    } else {
      // Clear storage when tokens are cleared
      localStorage.removeItem(AUTH_TOKEN_KEY)
      localStorage.removeItem(ZUSTAND_STORAGE_KEY)
      logger.debug('Cleared session from storage', {}, 'AuthMachine')
    }
  } catch (error) {
    logger.warn('Failed to persist session to storage', {
      error: error instanceof Error ? error.message : String(error),
    }, 'AuthMachine')
  }
}

/**
 * Configuration for createAuthMachineStore factory
 */
export interface AuthMachineStoreConfig {
  /** Apollo Client instance (dependency injection) */
  apolloClient: ApolloClient<NormalizedCacheObject>
  /** Optional custom logger */
  logger?: Logger
  /** Callback when user logs in */
  onLogin?: (user: AuthUser) => void
  /** Callback when user logs out */
  onLogout?: () => void
  /** Callback on auth error */
  onError?: (error: AppError) => void
}

/**
 * Auth machine store state interface
 *
 * All state is DERIVED from the XState machine - no manual state management here
 */
export interface AuthMachineState {
  // Derived state from machine
  user: AuthUser | null
  tokens: AuthTokens | null
  isAuthenticated: boolean
  /** Loading for initial operations (login, logout, checkAuth) */
  isLoading: boolean
  /** Separate flag for background refresh - does NOT affect UI */
  isRefreshing: boolean
  error: AppError | null
  /** Always true - no hydration needed (machine is source of truth) */
  hasHydrated: boolean
  /** Machine state string for debugging */
  machineState: string

  // WORLD-CLASS SESSION HANDLING: Session state exposed for UI components
  /** When the current session started (for absolute timeout tracking) */
  sessionStartedAt: number | null
  /** Last user activity timestamp (for idle timeout tracking) */
  lastActivityAt: number | null
  /** Number of consecutive refresh attempts */
  refreshAttempts: number

  // Actions - delegate to machine
  login: (credentials: LoginCredentials) => void
  register: (data: SignupData) => Promise<RegisterResult>
  logout: () => void
  forceLogout: () => void
  refreshToken: () => void
  checkAuth: () => void
  clearError: () => void
  /** Set auth directly (used by OAuth callback) */
  setAuth: (data: { user: AuthUser; accessToken: string; refreshToken: string; sessionId?: string; expiresIn?: number }) => void

  // Direct access
  getAccessToken: () => string | null

  /**
   * WORLD-CLASS SESSION HANDLING: Send events to the auth machine
   * Used by idle timeout hook to send USER_ACTIVITY, IDLE_TIMEOUT, etc.
   */
  sendEvent: (event: { type: string }) => void

  // Internal - expose actor for advanced use cases
  _actor: AnyActorRef
}

/**
 * Type for machine snapshots
 */
type AuthSnapshot = Snapshot<AuthContext>

/**
 * Derive store state from machine snapshot
 */
function deriveStateFromSnapshot(
  snapshot: AuthSnapshot | undefined | null,
  logger: Logger
): Partial<AuthMachineState> {
  // Defensive check - if snapshot is invalid, return safe defaults
  if (!snapshot || typeof snapshot.matches !== 'function') {
    logger.warn('Invalid snapshot received', { snapshot: typeof snapshot }, 'AuthMachine')
    return {
      user: null,
      tokens: null,
      error: null,
      isAuthenticated: false,
      isLoading: true, // Assume loading until we get a valid snapshot
      isRefreshing: false,
      machineState: '"unknown"',
      // WORLD-CLASS SESSION HANDLING: Default session state
      sessionStartedAt: null,
      lastActivityAt: null,
      refreshAttempts: 0,
    }
  }

  const machineState = JSON.stringify(snapshot.value)

  // Log state transitions for debugging
  logger.debug('Machine state changed', { state: machineState }, 'AuthMachine')

  return {
    // Context values
    user: snapshot.context?.user ?? null,
    tokens: snapshot.context?.tokens ?? null,
    error: snapshot.context?.error
      ? new AppError(
          snapshot.context.error.message,
          snapshot.context.error.code,
          'medium'
        )
      : null,

    // CRITICAL: Derive boolean flags from machine state
    // These are deterministic based on which state the machine is in
    isAuthenticated: snapshot.matches('authenticated'),

    // isLoading for initial operations only (NOT background refresh)
    // Includes 'initializing' state which immediately transitions to checkingAuth
    isLoading:
      snapshot.matches('initializing') ||
      snapshot.matches('loggingIn') ||
      snapshot.matches('loggingOut') ||
      snapshot.matches('checkingAuth') ||
      snapshot.matches('registering'),

    // isRefreshing for background operations (nested under authenticated)
    // This does NOT affect isAuthenticated or isLoading
    isRefreshing: snapshot.matches({ authenticated: 'refreshingToken' }),

    // WORLD-CLASS SESSION HANDLING: Expose session state from machine context
    sessionStartedAt: snapshot.context?.sessionStartedAt ?? null,
    lastActivityAt: snapshot.context?.lastActivityAt ?? null,
    refreshAttempts: snapshot.context?.refreshAttempts ?? 0,

    // Debug info
    machineState,
  }
}

/**
 * Factory function to create auth machine store
 *
 * This creates a Zustand store that:
 * 1. Creates and starts an XState auth machine
 * 2. Subscribes to machine state changes
 * 3. Derives all state from the machine (no manual state)
 * 4. Delegates all actions to the machine
 *
 * @param config - Configuration including Apollo client and callbacks
 * @returns Zustand store hook
 */
export function createAuthMachineStore(
  config: AuthMachineStoreConfig
): UseBoundStore<StoreApi<AuthMachineState>> {
  const { apolloClient, logger = defaultLogger, onLogin, onLogout, onError } = config

  // Track previous state for change detection
  let previousState: string | null = null

  // CRITICAL: Restore FULL session (tokens + user) from localStorage BEFORE creating store
  // This enables the optimization to skip checkAuth when we have valid tokens AND user
  const restoredSession = restoreSessionFromStorage(logger)
  const { tokens: restoredTokens, user: restoredUser, tokenValid, sessionStartedAt: restoredSessionStartedAt } = restoredSession

  // WORLD-CLASS: Check if session has exceeded absolute timeout (24 hours default)
  const absoluteTimeoutMs = 24 * 60 * 60 * 1000 // 24 hours
  const sessionAge = restoredSessionStartedAt ? Date.now() - restoredSessionStartedAt : 0
  const sessionExpiredAbsolute = restoredSessionStartedAt !== null && sessionAge > absoluteTimeoutMs

  // Determine if we can skip the initial checkAuth
  // We can skip if we have:
  // 1. Valid (non-expired) access token
  // 2. User data in localStorage
  // 3. Session has NOT exceeded absolute timeout (WORLD-CLASS)
  // This enables instant authentication state on page reload
  const canSkipInitialCheck = tokenValid && restoredUser !== null && !sessionExpiredAbsolute

  logger.info('Session restoration decision', {
    hasTokens: !!restoredTokens,
    hasUser: !!restoredUser,
    tokenValid,
    sessionStartedAt: restoredSessionStartedAt,
    sessionAgeMinutes: Math.round(sessionAge / 60000),
    sessionExpiredAbsolute,
    canSkipInitialCheck,
  }, 'AuthMachine')

  if (restoredTokens?.accessToken) {
    // Set the access token immediately so Apollo can use it
    // This is set BEFORE the machine starts, ensuring any service has a token
    setAccessToken(restoredTokens.accessToken)
    logger.info('Pre-set access token for Apollo Client', {}, 'AuthMachine')
  }

  return create<AuthMachineState>()((set, get) => {
    // 1. Create the XState machine with Apollo client, restored session, and skip flag
    const machine = createAuthMachine({
      apolloClient,
      logger: {
        info: logger.info,
        warn: logger.warn,
        error: logger.error,
        debug: logger.debug,
      },
      // CRITICAL: Pass restored tokens to machine so context.tokens is set from the start
      initialTokens: restoredTokens,
      // CRITICAL: Pass restored user to machine so context.user is set from the start
      initialUser: restoredUser,
      // CRITICAL: Skip checkAuth if we have valid tokens AND user
      // This enables instant authentication state on page reload
      skipInitialCheck: canSkipInitialCheck,
      // WORLD-CLASS: Preserve session start time for absolute timeout tracking
      sessionStartedAt: restoredSessionStartedAt,
    })

    // 2. Create the actor
    const actor = createActor(machine)

    // 3. Subscribe to machine state changes
    actor.subscribe((snapshot) => {
      // Defensive check - skip processing if snapshot is invalid
      if (!snapshot || typeof snapshot.matches !== 'function') {
        logger.warn('Invalid snapshot in subscription, skipping', { snapshot: typeof snapshot }, 'AuthMachine')
        return
      }

      const newState = deriveStateFromSnapshot(snapshot, logger)

      // Update Zustand store with derived state
      set(newState)

      // CRITICAL: Persist session to localStorage for session recovery on page reload
      // WORLD-CLASS: Now includes sessionStartedAt for absolute timeout tracking
      persistSessionToStorage(
        snapshot.context?.tokens ?? null,
        snapshot.context?.user ?? null,
        snapshot.context?.sessionStartedAt ?? null,
        logger
      )

      // Trigger callbacks on state transitions
      const currentMachineState = JSON.stringify(snapshot.value)
      const isNowAuthenticated = currentMachineState.includes('authenticated')
      const wasAuthenticated = previousState?.includes('authenticated') ?? false
      const isNowIdle = currentMachineState === '"idle"'

      // DEBUG: Log all state transitions for troubleshooting auth issues
      logger.info('🔄 State transition', {
        previousState,
        currentState: currentMachineState,
        isNowAuthenticated,
        wasAuthenticated,
        isNowIdle,
        hasUser: !!snapshot.context?.user,
        hasTokens: !!snapshot.context?.tokens,
        refreshAttempts: snapshot.context?.refreshAttempts,
      }, 'AuthMachine')

      // Detect login transition
      // Trigger when:
      // 1. We're now in 'authenticated' state
      // 2. We were NOT in 'authenticated' state before (including null/first subscription)
      // 3. Special case: previousState was a login-related state (loggingIn, checkingAuth)
      //    This ensures the callback fires on fresh login, not just session restore
      const wasLoggingIn = previousState?.includes('loggingIn') ?? false
      const wasCheckingAuth = previousState?.includes('checkingAuth') ?? false
      const isLoginTransition = isNowAuthenticated &&
        !wasAuthenticated &&
        (wasLoggingIn || wasCheckingAuth) &&
        snapshot.context?.user

      if (isLoginTransition && onLogin) {
        logger.info('✅ Login callback triggered', { userId: snapshot.context.user!.id, previousState }, 'AuthMachine')
        onLogin(snapshot.context.user!)
      }

      // Detect logout transition
      // When user logs out, the machine goes from authenticated state to idle
      // The previousState will be either '{"authenticated":"idle"}' or '{"authenticated":"refreshingToken"}'
      // and currentMachineState will be '"idle"'
      // Also detect transition from loggingOut to idle
      const wasInLogoutFlow = previousState?.includes('loggingOut') ?? false
      if ((wasAuthenticated || wasInLogoutFlow) && isNowIdle && onLogout) {
        logger.info('🚪 Logout callback triggered', {
          wasAuthenticated,
          wasInLogoutFlow,
          previousState,
          currentState: currentMachineState,
        }, 'AuthMachine')
        onLogout()
      }

      // Detect error transition
      if (currentMachineState === '"error"' && snapshot.context?.error && onError) {
        logger.info('Error callback triggered', { error: snapshot.context.error }, 'AuthMachine')
        onError(
          new AppError(
            snapshot.context.error.message,
            snapshot.context.error.code,
            'medium'
          )
        )
      }

      previousState = currentMachineState
    })

    // 4. Start the machine
    actor.start()
    logger.info('Auth machine started', {}, 'AuthMachine')

    // 5. Register token provider so Apollo can access tokens
    registerTokenProvider(
      () => get().tokens?.accessToken ?? null,
      (token: string | null) => {
        // Token updates come from machine, not external setters
        // This is mainly for compatibility with existing code
        if (token === null) {
          actor.send({ type: 'FORCE_LOGOUT' })
        }
      }
    )

    // 6. Return store interface
    // CRITICAL: Initial state depends on whether we're skipping checkAuth
    // When skipInitialCheck=true, we start in authenticated state with restored data
    // When skipInitialCheck=false, we start in loading state
    return {
      // Initial state (will be updated by subscription immediately after actor.start())
      // When canSkipInitialCheck=true: Start authenticated with restored data
      // When canSkipInitialCheck=false: Start loading (machine checks auth)
      user: canSkipInitialCheck ? restoredUser : null,
      tokens: canSkipInitialCheck ? restoredTokens : null,
      isAuthenticated: canSkipInitialCheck,
      isLoading: !canSkipInitialCheck, // Only loading if we need to check auth
      isRefreshing: false,
      error: null,
      hasHydrated: true, // Always true - machine handles state
      machineState: canSkipInitialCheck ? '{"authenticated":"idle"}' : '"initializing"',
      // WORLD-CLASS SESSION HANDLING: Initial session state
      sessionStartedAt: canSkipInitialCheck ? restoredSessionStartedAt : null,
      lastActivityAt: canSkipInitialCheck ? Date.now() : null,
      refreshAttempts: 0,

      // Actions - all delegate to machine
      login: (credentials) => {
        logger.info('Login requested', { email: credentials.email }, 'AuthMachine')
        actor.send({ type: 'LOGIN', credentials })
      },

      register: async (data) => {
        logger.info('Register requested', { email: data.email }, 'AuthMachine')
        actor.send({ type: 'REGISTER', data })

        // Wait for machine to complete registration
        return new Promise<RegisterResult>((resolve, reject) => {
          const subscription = actor.subscribe((snapshot) => {
            // Registration completed (back to idle)
            if (snapshot.matches('idle') && previousState?.includes('registering')) {
              subscription.unsubscribe()
              // Note: Registration result needs to be extracted from context
              // For now, return a basic result
              resolve({
                verificationRequired: true,
                message: 'Please check your email to verify your account',
                userId: '',
                email: data.email,
              })
            }

            // Registration failed
            if (snapshot.matches('error')) {
              subscription.unsubscribe()
              reject(
                new AppError(
                  snapshot.context.error?.message || 'Registration failed',
                  'ValidationError',
                  'medium'
                )
              )
            }
          })
        })
      },

      logout: () => {
        logger.info('Logout requested', {}, 'AuthMachine')
        actor.send({ type: 'LOGOUT' })
      },

      forceLogout: () => {
        logger.info('Force logout requested', {}, 'AuthMachine')
        actor.send({ type: 'FORCE_LOGOUT' })
      },

      refreshToken: () => {
        logger.info('Token refresh requested', {}, 'AuthMachine')
        actor.send({ type: 'REFRESH_TOKEN' })
      },

      checkAuth: () => {
        logger.info('Check auth requested', {}, 'AuthMachine')
        actor.send({ type: 'CHECK_AUTH' })
      },

      clearError: () => {
        logger.info('Clear error requested', {}, 'AuthMachine')
        actor.send({ type: 'CLEAR_ERROR' })
      },

      setAuth: (data) => {
        logger.info('Set auth requested (OAuth callback)', { userId: data.user.id }, 'AuthMachine')
        const tokens: AuthTokens = {
          accessToken: data.accessToken,
          refreshToken: data.refreshToken,
          expiresIn: data.expiresIn ?? 3600,
          tokenType: 'Bearer',
          sessionId: data.sessionId,
        }
        actor.send({ type: 'SET_AUTH', user: data.user, tokens })
      },

      getAccessToken: () => get().tokens?.accessToken ?? null,

      /**
       * WORLD-CLASS SESSION HANDLING: Send events to the auth machine
       *
       * Allows external components (like idle timeout hook) to send
       * session-related events to the machine:
       * - USER_ACTIVITY: User performed an action
       * - IDLE_WARNING: About to be logged out
       * - IDLE_TIMEOUT: Logged out due to inactivity
       * - ABSOLUTE_TIMEOUT: Session expired (max duration)
       * - EXTEND_SESSION: User chose to extend session
       */
      sendEvent: (event: { type: string }) => {
        logger.debug('External event sent to machine', { event: event.type }, 'AuthMachine')
        actor.send(event as AuthEvent)
      },

      // Expose actor for advanced use cases
      _actor: actor,
    }
  })
}

/**
 * Export types for consumers
 */
export type { AuthMachineState, AuthMachineStoreConfig, Logger }
