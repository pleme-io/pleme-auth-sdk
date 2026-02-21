/**
 * useAuthMachine Hook
 *
 * React hook for using the XState auth machine.
 * Provides a clean API for React components to interact with auth state.
 */

import { useMemo, useCallback } from 'react'
import { useMachine } from '@xstate/react'
import type { ApolloClient, NormalizedCacheObject } from '@apollo/client'
import type { LoginCredentials, SignupData, AuthUser, AuthTokens } from '@pleme/types'
import { createAuthMachine, getAccessToken, type AuthLogger } from './authMachine'
import type { AuthContext, AuthError, RegisterResult } from './authMachine.types'

/**
 * Configuration for useAuthMachine hook
 */
export interface UseAuthMachineConfig {
  /** Apollo Client instance */
  apolloClient: ApolloClient<NormalizedCacheObject>
  /** Optional custom logger */
  logger?: AuthLogger
}

/**
 * Return type for useAuthMachine hook
 */
export interface UseAuthMachineReturn {
  // State
  /** Current authenticated user */
  user: AuthUser | null
  /** Current tokens (in-memory) */
  tokens: AuthTokens | null
  /** Whether user is authenticated */
  isAuthenticated: boolean
  /** Whether an auth operation is in progress */
  isLoading: boolean
  /** Current auth error */
  error: AuthError | null
  /** Current machine state value */
  state: string
  /** Full machine context */
  context: AuthContext

  // Actions
  /** Login with credentials */
  login: (credentials: LoginCredentials) => void
  /** Register new user */
  register: (data: SignupData) => Promise<RegisterResult | undefined>
  /** Logout current user */
  logout: () => void
  /** Force logout (no backend call) */
  forceLogout: () => void
  /** Check current auth status */
  checkAuth: () => void
  /** Manually trigger token refresh */
  refreshToken: () => void
  /** Set auth state directly (for admin login-as-user) */
  setAuth: (user: AuthUser, tokens: AuthTokens) => void
  /** Clear current error */
  clearError: () => void

  // Utilities
  /** Get current access token (for Apollo authLink) */
  getAccessToken: () => string | null
  /** Whether machine can accept LOGIN event */
  canLogin: boolean
  /** Whether machine can accept LOGOUT event */
  canLogout: boolean
}

/**
 * Loading states for the machine
 */
const LOADING_STATES = [
  'loggingIn',
  'registering',
  'loggingOut',
  'refreshingToken',
  'checkingAuth',
] as const

/**
 * useAuthMachine Hook
 *
 * @example
 * ```tsx
 * const { login, logout, user, isAuthenticated, isLoading, error } = useAuthMachine({
 *   apolloClient,
 *   logger: customLogger,
 * })
 *
 * // Login
 * const handleLogin = () => {
 *   login({ email: 'user@example.com', password: 'password' })
 * }
 *
 * // Check auth on mount
 * useEffect(() => {
 *   checkAuth()
 * }, [checkAuth])
 * ```
 */
export function useAuthMachine(config: UseAuthMachineConfig): UseAuthMachineReturn {
  const { apolloClient, logger } = config

  // Create machine with dependencies
  const machine = useMemo(
    () => createAuthMachine({ apolloClient, logger }),
    [apolloClient, logger]
  )

  // Use the machine - state is already reactive
  const [snapshot, send] = useMachine(machine)

  // Derive values from snapshot
  const user = snapshot.context.user
  const tokens = snapshot.context.tokens
  const error = snapshot.context.error

  // Computed values
  const isAuthenticated = snapshot.matches('authenticated')
  const isLoading = LOADING_STATES.some((s) => snapshot.matches(s))
  const stateValue =
    typeof snapshot.value === 'string' ? snapshot.value : JSON.stringify(snapshot.value)

  // Actions
  const login = useCallback(
    (credentials: LoginCredentials) => {
      send({ type: 'LOGIN', credentials })
    },
    [send]
  )

  const register = useCallback(
    async (data: SignupData): Promise<RegisterResult | undefined> => {
      // Note: For register, we need to handle the async result
      // The machine handles the mutation, but we need to extract the result
      // This is a limitation - consider using actors directly for async results
      send({ type: 'REGISTER', data })
      // Return undefined - caller should watch for state changes
      return undefined
    },
    [send]
  )

  const logout = useCallback(() => {
    send({ type: 'LOGOUT' })
  }, [send])

  const forceLogout = useCallback(() => {
    send({ type: 'FORCE_LOGOUT' })
  }, [send])

  const checkAuth = useCallback(() => {
    send({ type: 'CHECK_AUTH' })
  }, [send])

  const refreshTokenAction = useCallback(() => {
    send({ type: 'REFRESH_TOKEN' })
  }, [send])

  const setAuth = useCallback(
    (authUser: AuthUser, authTokens: AuthTokens) => {
      send({ type: 'SET_AUTH', user: authUser, tokens: authTokens })
    },
    [send]
  )

  const clearError = useCallback(() => {
    send({ type: 'CLEAR_ERROR' })
  }, [send])

  // Can guards
  const canLogin = snapshot.can({ type: 'LOGIN', credentials: {} as LoginCredentials })
  const canLogout = snapshot.can({ type: 'LOGOUT' })

  return {
    // State
    user,
    tokens,
    isAuthenticated,
    isLoading,
    error,
    state: stateValue,
    context: snapshot.context,

    // Actions
    login,
    register,
    logout,
    forceLogout,
    checkAuth,
    refreshToken: refreshTokenAction,
    setAuth,
    clearError,

    // Utilities
    getAccessToken,
    canLogin,
    canLogout,
  }
}
