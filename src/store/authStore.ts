/**
 * Authentication Store (v4.0 - Simplified In-Memory Architecture)
 *
 * ARCHITECTURAL DECISION:
 * This version REMOVES localStorage persistence for tokens entirely.
 * This eliminates all race conditions caused by stale token rehydration.
 *
 * TOKEN STORAGE STRATEGY:
 * - Access Token: In-memory only (this store's context)
 * - Refresh Token: HttpOnly cookie (server-managed, secure)
 * - User data: In-memory (re-fetched on page load if needed)
 *
 * WHY NO LOCALSTORAGE FOR TOKENS:
 * 1. Stale tokens cause "Invalid token" errors on rehydration
 * 2. localStorage is vulnerable to XSS attacks
 * 3. Race conditions between persist middleware and navigation
 * 4. HttpOnly cookies are the industry standard (Auth0, Okta, Firebase)
 *
 * ON PAGE REFRESH:
 * - checkAuth() is called to validate session via HttpOnly cookie
 * - If valid, server returns user data and new access token
 * - If invalid, user is logged out (expected behavior)
 */

import { ApolloError, type ApolloClient, type NormalizedCacheObject } from '@apollo/client'
import { create, type UseBoundStore, type StoreApi } from 'zustand'
import type {
  AuthTokens,
  AuthUser,
  LoginCredentials,
  SignupData,
  RegisterResult,
  UserRole,
} from '@pleme/types'
import { AppError } from '@pleme/types'
import { getSecondsUntilExpiry, isTokenExpired } from '../utils/jwt'
import {
  LOGIN_MUTATION,
  LOGOUT_MUTATION,
  ME_QUERY,
  REFRESH_TOKEN_MUTATION,
  REGISTER_MUTATION,
} from './auth.graphql'
// Import token provider registration for unified auth
import { registerTokenProvider } from '../machines/authMachine'
// Import auth handlers registry to auto-register when store is created
import { registerAuthHandlers } from '../machines/authHandlers'

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
    console.log(`[${category || 'Auth'}] ${message}`, context || ''),
  warn: (message, context, category) =>
    console.warn(`[${category || 'Auth'}] ${message}`, context || ''),
  error: (message, context, category) =>
    console.error(`[${category || 'Auth'}] ${message}`, context || ''),
  debug: (message, context, category) =>
    console.debug(`[${category || 'Auth'}] ${message}`, context || ''),
}

/**
 * Configuration for createAuthStore factory
 */
export interface AuthStoreConfig {
  /** Apollo Client instance (dependency injection) */
  apolloClient: ApolloClient<NormalizedCacheObject>
  /** Optional custom logger */
  logger?: Logger
  /** Storage name (kept for backwards compatibility, but NOT used for tokens) */
  storageName?: string
}

/**
 * Auth state interface
 */
export interface AuthState {
  // State
  user: AuthUser | null
  tokens: AuthTokens | null
  isAuthenticated: boolean
  isLoading: boolean
  /** Separate flag for background token refresh - does NOT affect UI/isAuthReady */
  isRefreshing: boolean
  error: AppError | null
  hasHydrated: boolean
  refreshTimerId: ReturnType<typeof setTimeout> | null

  // Actions
  login: (credentials: LoginCredentials) => Promise<void>
  register: (data: SignupData) => Promise<RegisterResult>
  logout: () => Promise<void>
  forceLogout: () => void
  refreshToken: () => Promise<void>
  checkAuth: () => Promise<void>
  clearError: () => void

  // Token management
  scheduleTokenRefresh: () => void
  cancelTokenRefresh: () => void
  setAuth: (authData: { user: AuthUser; tokens: AuthTokens }) => Promise<void>
  getAccessToken: () => string | null

  // Internal actions
  setUser: (user: AuthUser | null) => void
  setTokens: (tokens: AuthTokens | null) => void
  setLoading: (loading: boolean) => void
  setError: (error: AppError | null) => void
  setHydrated: (hydrated: boolean) => void
}

// Note: getAccessToken is now exported from machines/authMachine.ts
// which delegates to the registered token provider (this store)

/**
 * Factory function to create auth store with dependency injection
 *
 * @param config - Configuration including Apollo client and optional logger
 * @returns Zustand store hook
 */
export function createAuthStore(
  config: AuthStoreConfig
): UseBoundStore<StoreApi<AuthState>> {
  const { apolloClient, logger = defaultLogger } = config

  const store = create<AuthState>()((set, get) => ({
    // Initial state - always starts unauthenticated
    user: null,
    tokens: null,
    isAuthenticated: false,
    isLoading: false,
    isRefreshing: false, // Separate flag for background refresh - doesn't affect UI
    error: null,
    hasHydrated: true, // No hydration needed - always starts fresh
    refreshTimerId: null,

    // Actions
    login: async (credentials: LoginCredentials) => {
      // Clear any existing state first
      get().cancelTokenRefresh()

      set({ isLoading: true, error: null, user: null, tokens: null, isAuthenticated: false })

      try {
        const loginInput: Record<string, string | boolean | undefined> = {
          email: credentials.email,
          cpf: credentials.cpf,
          password: credentials.password,
        }

        if (credentials.rememberMe !== undefined) {
          loginInput.rememberMe = credentials.rememberMe
        }

        logger.info('Login request', { email: credentials.email }, 'Auth')

        const { data: result } = await apolloClient.mutate({
          mutation: LOGIN_MUTATION,
          variables: { input: loginInput },
        })

        if (result?.login?.user && result?.login?.accessToken) {
          const authUser: AuthUser = {
            id: result.login.user.id,
            email: result.login.user.email,
            username: result.login.user.username,
            firstName:
              result.login.user.firstName || result.login.user.displayName?.split(' ')[0] || '',
            lastName:
              result.login.user.lastName ||
              result.login.user.displayName?.split(' ').slice(1).join(' ') ||
              '',
            cpf: result.login.user.cpf,
            phoneNumber: result.login.user.phoneNumber,
            roles: result.login.user.roles ||
              (result.login.user.role ? [result.login.user.role as UserRole] : ['customer']),
            permissions: result.login.user.permissions || [],
            emailVerified: result.login.user.emailVerified,
            secondaryEmail: result.login.user.secondaryEmail,
            secondaryEmailVerified: result.login.user.secondaryEmailVerified || false,
            createdAt: result.login.user.createdAt || new Date().toISOString(),
            updatedAt: result.login.user.updatedAt || new Date().toISOString(),
          }

          const authTokens: AuthTokens = {
            accessToken: result.login.accessToken,
            refreshToken: result.login.refreshToken || '',
            expiresIn: result.login.expiresIn,
            tokenType: 'Bearer',
            sessionId: result.login.sessionId,
          }

          // Token is stored in Zustand state - token provider reads from here
          set({
            user: authUser,
            tokens: authTokens,
            isAuthenticated: true,
            isLoading: false,
            error: null,
          })

          get().scheduleTokenRefresh()

          logger.info('Login successful', { userId: authUser.id }, 'Auth')
        } else {
          throw new Error('Login failed: Invalid response from server')
        }
      } catch (error) {
        logger.error('Login failed', {
          error: (error as Error)?.message || String(error),
        }, 'Auth')

        let userMessage = 'Falha no login. Verifique suas credenciais.'

        if (error instanceof ApolloError) {
          const graphQLErrors = error.graphQLErrors
          if (graphQLErrors && graphQLErrors.length > 0) {
            const errorMsg = graphQLErrors[0].message.toLowerCase()
            if (errorMsg.includes('cpf')) {
              userMessage = 'CPF inválido ou não corresponde ao cadastro.'
            } else if (errorMsg.includes('password') || errorMsg.includes('senha')) {
              userMessage = 'Senha incorreta. Tente novamente ou recupere sua senha.'
            } else if (errorMsg.includes('email')) {
              userMessage = 'Email não encontrado. Verifique o email ou crie uma nova conta.'
            }
          }
        }

        const appError = new AppError(userMessage, 'InvalidCredentials', 'medium', {
          originalError: (error as Error)?.message || String(error),
        })

        set({
          error: appError,
          isLoading: false,
          user: null,
          tokens: null,
          isAuthenticated: false,
        })
        throw appError
      }
    },

    register: async (data: SignupData) => {
      set({ isLoading: true, error: null })

      try {
        const registerInput: Record<string, string | boolean | undefined> = {
          email: data.email,
          displayName: data.displayName,
          password: data.password,
          confirmPassword: data.confirmPassword,
          termsAccepted: data.acceptsTerms,
        }

        if (data.firstName) registerInput.firstName = data.firstName
        if (data.lastName) registerInput.lastName = data.lastName
        if (data.cpf) registerInput.cpf = data.cpf
        if (data.phoneNumber) registerInput.phoneNumber = data.phoneNumber

        const { data: result } = await apolloClient.mutate({
          mutation: REGISTER_MUTATION,
          variables: { input: registerInput },
        })

        if (result?.register?.user) {
          set({
            user: null,
            isAuthenticated: false,
            isLoading: false,
            error: null,
          })

          return {
            verificationRequired: result.register.verificationRequired,
            message: result.register.message,
            userId: result.register.user.id,
            email: result.register.user.email,
          }
        } else {
          throw new Error('Registration failed: No user data returned')
        }
      } catch (error) {
        const appError =
          error instanceof ApolloError
            ? new AppError(error.message || 'Registration failed', 'ValidationError', 'medium', {
                error: (error as Error)?.message || String(error),
              })
            : (error as AppError)

        set({
          error: appError,
          isLoading: false,
          user: null,
          isAuthenticated: false,
        })
        throw appError
      }
    },

    logout: async () => {
      set({ isLoading: true, error: null })
      get().cancelTokenRefresh()

      try {
        const { tokens } = get()
        logger.info('Logout request', { hasSessionId: !!tokens?.sessionId }, 'Auth')

        if (tokens?.accessToken && tokens?.sessionId) {
          try {
            await apolloClient.mutate({
              mutation: LOGOUT_MUTATION,
              variables: { sessionId: tokens.sessionId },
            })
            logger.info('Backend logout successful', {}, 'Auth')
          } catch (backendError) {
            logger.warn('Backend logout failed (continuing with local cleanup)', {
              error: backendError,
            }, 'Auth')
          }
        }

        // Clear state (token provider reads from state)
        await apolloClient.clearStore()

        set({
          user: null,
          tokens: null,
          isAuthenticated: false,
          isLoading: false,
          error: null,
        })
      } catch (_error) {
        try {
          await apolloClient.clearStore()
        } catch (cacheError) {
          logger.error('Failed to clear Apollo cache', { error: cacheError }, 'Auth')
        }

        set({
          user: null,
          tokens: null,
          isAuthenticated: false,
          isLoading: false,
          error: null,
        })
      }
    },

    /**
     * Force logout - synchronously clears all local auth state without backend call
     */
    forceLogout: () => {
      get().cancelTokenRefresh()

      set({
        user: null,
        tokens: null,
        isAuthenticated: false,
        isLoading: false,
        error: null,
      })

      logger.info('Force logout complete', {}, 'Auth')
    },

    refreshToken: async () => {
      const { tokens } = get()

      // refreshToken can be empty when AUTH_COOKIES_ENABLED=true on backend
      // In that case, the server uses the HttpOnly cookie for refresh
      const refreshTokenValue = tokens?.refreshToken && tokens.refreshToken.trim() !== ''
        ? tokens.refreshToken
        : null

      // NOTE: We intentionally DO NOT throw if both tokens are missing.
      // When AUTH_COOKIES_ENABLED=true, the backend accepts null refreshToken
      // and uses the HttpOnly cookie instead. This enables session restoration
      // after page refresh when in-memory tokens are lost.

      // CRITICAL: Use isRefreshing instead of isLoading for background refresh
      // This prevents UI flicker during token refresh while user is authenticated
      // isLoading is for initial auth operations (login, logout, checkAuth)
      // isRefreshing is for background operations that shouldn't affect UI
      set({ isRefreshing: true, error: null })

      try {
        const { data } = await apolloClient.mutate({
          mutation: REFRESH_TOKEN_MUTATION,
          variables: { refreshToken: refreshTokenValue },
        })

        if (data?.refreshToken) {
          const updatedTokens: AuthTokens = {
            ...tokens,
            accessToken: data.refreshToken.accessToken,
            refreshToken: data.refreshToken.refreshToken || tokens?.refreshToken,
            expiresIn: data.refreshToken.expiresIn,
          }

          // Token is stored in Zustand state - token provider reads from here
          set({
            tokens: updatedTokens,
            isRefreshing: false, // Use isRefreshing, not isLoading
            error: null,
          })

          get().scheduleTokenRefresh()
          logger.info('Token refreshed successfully', {}, 'Auth')
        } else {
          throw new Error('Invalid refresh token response')
        }
      } catch (error) {
        const appError =
          error instanceof ApolloError
            ? new AppError(error.message || 'Token refresh failed', 'Unauthorized', 'medium', {
                error: (error as Error)?.message || String(error),
              })
            : new AppError('Token refresh failed', 'Unauthorized', 'medium', {
                error: (error as Error)?.message || String(error),
              })

        set({
          error: appError,
          isRefreshing: false, // Clear isRefreshing, not isLoading
          user: null,
          tokens: null,
          isAuthenticated: false,
        })
        throw appError
      }
    },

    checkAuth: async () => {
      set({ isLoading: true, error: null })

      try {
        const { data } = await apolloClient.query({
          query: ME_QUERY,
          fetchPolicy: 'network-only',
        })

        if (data?.me) {
          const authUser: AuthUser = {
            id: data.me.id,
            email: data.me.email,
            username: data.me.username,
            firstName: data.me.firstName || data.me.displayName?.split(' ')[0] || '',
            lastName:
              data.me.lastName || data.me.displayName?.split(' ').slice(1).join(' ') || '',
            cpf: data.me.cpf,
            phoneNumber: data.me.phoneNumber,
            roles: data.me.roles ||
              (data.me.role ? [data.me.role as UserRole] : ['customer']),
            permissions: data.me.permissions || [],
            emailVerified: data.me.emailVerified,
            secondaryEmail: data.me.secondaryEmail,
            secondaryEmailVerified: data.me.secondaryEmailVerified || false,
            createdAt: data.me.createdAt || new Date().toISOString(),
            updatedAt: data.me.updatedAt || new Date().toISOString(),
          }

          set({
            user: authUser,
            isAuthenticated: true,
            isLoading: false,
            error: null,
          })

          logger.info('Auth check successful', { userId: authUser.id }, 'Auth')
        } else {
          set({
            user: null,
            tokens: null,
            isAuthenticated: false,
            isLoading: false,
            error: null,
          })
        }
      } catch (error) {
        const isAuthError =
          error instanceof ApolloError &&
          error.graphQLErrors?.some(
            (e) =>
              e.extensions?.code === 'UNAUTHENTICATED' || e.extensions?.code === 'FORBIDDEN'
          )

        if (isAuthError) {
          try {
            await apolloClient.clearStore()
          } catch (cacheError) {
            logger.error('Failed to clear Apollo cache', { error: cacheError }, 'Auth')
          }

          set({
            user: null,
            tokens: null,
            isAuthenticated: false,
            isLoading: false,
            error: new AppError('Sessão inválida ou expirada', 'Unauthorized', 'medium'),
          })
        } else {
          logger.warn('Network error during checkAuth - keeping session', {
            error: (error as Error)?.message,
          }, 'Auth')

          set({
            isLoading: false,
            error: new AppError(
              'Erro de rede ao verificar sessão. Tente novamente.',
              'NetworkError',
              'low'
            ),
          })
        }
      }
    },

    clearError: () => {
      set({ error: null })
    },

    // Token management
    scheduleTokenRefresh: () => {
      const { tokens, refreshTimerId } = get()

      if (refreshTimerId) {
        clearTimeout(refreshTimerId)
      }

      // Token is stored in Zustand state - read from there
      const accessToken = tokens?.accessToken
      if (!accessToken) {
        logger.debug('No access token - skipping refresh scheduling', {}, 'Auth')
        return
      }

      const secondsUntilExpiry = getSecondsUntilExpiry(accessToken)
      if (secondsUntilExpiry === null) {
        logger.warn('Cannot schedule refresh - invalid token', {}, 'Auth')
        return
      }

      const REFRESH_BUFFER_SECONDS = 60 // 1 minute before expiry
      const refreshInSeconds = Math.max(0, secondsUntilExpiry - REFRESH_BUFFER_SECONDS)
      const refreshInMs = refreshInSeconds * 1000

      logger.info('Scheduling token refresh', {
        expiresIn: secondsUntilExpiry,
        refreshIn: refreshInSeconds,
      }, 'Auth')

      const timerId = setTimeout(async () => {
        // CRITICAL: Guards to prevent refresh race conditions
        const state = get()

        // Guard 1: Don't refresh if an auth operation is in progress
        if (state.isLoading) {
          logger.info('Skipping scheduled refresh - auth operation in progress', {}, 'Auth')
          return
        }

        // Guard 2: Don't refresh if we don't have a refresh token
        if (!state.tokens?.refreshToken) {
          logger.info('Skipping scheduled refresh - no refresh token available', {}, 'Auth')
          return
        }

        // Guard 3: Don't refresh if we're not authenticated
        if (!state.isAuthenticated) {
          logger.info('Skipping scheduled refresh - not authenticated', {}, 'Auth')
          return
        }

        logger.info('Auto-refreshing token', {}, 'Auth')
        try {
          await get().refreshToken()
        } catch (error) {
          logger.error('Auto-refresh failed', {
            error: (error as Error)?.message,
          }, 'Auth')
        }
      }, refreshInMs)

      set({ refreshTimerId: timerId })
    },

    cancelTokenRefresh: () => {
      const { refreshTimerId } = get()
      if (refreshTimerId) {
        clearTimeout(refreshTimerId)
        set({ refreshTimerId: null })
        logger.debug('Cancelled token refresh timer', {}, 'Auth')
      }
    },

    /**
     * Set authentication state directly
     * Used for admin login-as-user or external auth providers
     */
    setAuth: async (authData: { user: AuthUser; tokens: AuthTokens }) => {
      const { user, tokens } = authData

      // Token is stored in Zustand state - token provider reads from here
      set({
        user,
        tokens,
        isAuthenticated: true,
        isLoading: false,
        error: null,
      })

      get().scheduleTokenRefresh()

      logger.info('Auth state set directly', { userId: user.id }, 'Auth')
    },

    /**
     * Get current access token (for components that need it directly)
     */
    getAccessToken: () => get().tokens?.accessToken ?? null,

    // Internal actions
    setUser: (user) => {
      set({ user, isAuthenticated: !!user })
    },

    setTokens: (tokens) => {
      set({ tokens })
    },

    setLoading: (isLoading) => {
      set({ isLoading })
    },

    setError: (error) => {
      set({ error })
    },

    setHydrated: (hasHydrated) => {
      set({ hasHydrated })
    },
  }))

  // Auto-register auth handlers so Apollo error link can use this store
  // for token refresh when auth errors occur. This makes the Zustand store
  // work seamlessly with Apollo's error handling without requiring separate
  // XState machine initialization.
  registerAuthHandlers({
    onRefreshNeeded: async () => {
      // CRITICAL: Multiple guards to prevent race conditions during login
      const state = store.getState()

      // Guard 1: Don't attempt refresh if an auth operation is in progress
      if (state.isLoading) {
        logger.info('Skipping refresh - auth operation in progress', {}, 'Auth')
        return false
      }

      // Guard 2: Don't attempt refresh if we don't have a refresh token
      // This catches race conditions where login just completed but localStorage
      // hasn't persisted yet, and something triggers a refresh with stale state
      if (!state.tokens?.refreshToken) {
        logger.info('Skipping refresh - no refresh token available', {}, 'Auth')
        return false
      }

      // Guard 3: Don't attempt refresh if we're not authenticated
      // Extra safety to prevent unnecessary refresh attempts
      if (!state.isAuthenticated) {
        logger.info('Skipping refresh - not authenticated', {}, 'Auth')
        return false
      }

      try {
        await state.refreshToken()
        return true
      } catch (error) {
        logger.error('Auth handler refresh failed', { error }, 'Auth')
        return false
      }
    },
    onForceLogout: () => {
      // CRITICAL: Multiple guards to prevent race conditions during login
      const state = store.getState()

      // Guard 1: Don't force logout if login is in progress
      if (state.isLoading) {
        logger.info('Skipping force logout - auth operation in progress', {}, 'Auth')
        return
      }

      // Guard 2: Don't force logout if we're not authenticated
      // Prevents clearing state that was just set by a successful login
      if (!state.isAuthenticated) {
        logger.info('Skipping force logout - not authenticated', {}, 'Auth')
        return
      }

      state.forceLogout()
    },
    onClearToken: () => {
      // Clear token by clearing state
      store.setState({ tokens: null, isAuthenticated: false })
    },
  })

  // Register this store as the token provider
  // This makes Zustand the single source of truth for tokens
  // Apollo's getAccessToken() will read from this store
  registerTokenProvider(
    // Getter: returns token from Zustand state
    () => store.getState().tokens?.accessToken ?? null,
    // Setter: updates Zustand state
    (token: string | null) => {
      if (token === null) {
        store.setState({ tokens: null, isAuthenticated: false })
      } else {
        const currentTokens = store.getState().tokens
        if (currentTokens) {
          store.setState({ tokens: { ...currentTokens, accessToken: token } })
        }
      }
    }
  )

  logger.info('Auth store created, handlers registered, token provider configured', {}, 'Auth')

  return store
}

/**
 * Export types for consumers
 */
export type { AuthState, AuthStoreConfig, Logger }
