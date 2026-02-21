/**
 * XState Authentication Machine
 *
 * A finite state machine for managing authentication state.
 * Uses XState v5 with explicit typing and deterministic transitions.
 *
 * STATE DIAGRAM:
 * ```
 *  ┌─────────┐
 *  │  idle   │──CHECK_AUTH──►┌──────────────┐
 *  └────┬────┘               │ checkingAuth │
 *       │                    └──────┬───────┘
 *       │LOGIN                      │
 *       ▼                           ▼success
 *  ┌──────────┐              ┌──────────────┐◄───────────┐
 *  │loggingIn │──success────►│authenticated │            │
 *  └────┬─────┘              └──────┬───────┘            │
 *       │error                      │                    │
 *       ▼                           │LOGOUT              │
 *  ┌─────────┐                      ▼                    │
 *  │  error  │◄─────────────┌────────────┐               │
 *  └─────────┘              │ loggingOut │               │
 *                           └──────┬─────┘               │
 *                                  │                     │
 *                                  ▼                     │
 *                            ┌──────────┐                │
 *                            │   idle   │                │
 *                            └──────────┘                │
 *                                                        │
 *  TOKEN_EXPIRING from authenticated───►┌───────────────┐│
 *                                       │refreshingToken├┘
 *                                       └───────────────┘
 * ```
 *
 * DESIGN PRINCIPLES:
 * 1. Single source of truth - machine context is the ONLY auth state
 * 2. In-memory tokens - no localStorage (XSS safe, no stale token issues)
 * 3. HttpOnly cookies - refresh tokens managed by server
 * 4. Deterministic - every state has explicit transitions
 * 5. Testable - pure functions, injectable dependencies
 */

import { setup, assign, fromPromise, type AnyActorRef } from 'xstate'
import type { ApolloError } from '@apollo/client'
import type { AuthTokens, AuthUser, LoginCredentials, SignupData, UserRole } from '@pleme/types'
import { getSecondsUntilExpiry } from '../utils/jwt'
import {
  LOGIN_MUTATION,
  LOGOUT_MUTATION,
  ME_QUERY,
  REFRESH_TOKEN_MUTATION,
  REGISTER_MUTATION,
} from '../store/auth.graphql'
import type {
  AuthContext,
  AuthEvent,
  AuthLogger,
  AuthMachineInput,
  AuthError,
  LoginOutput,
  RefreshOutput,
  CheckAuthOutput,
  RegisterResult,
  SessionConfig,
} from './authMachine.types'
import { createAuthError, DEFAULT_SESSION_CONFIG } from './authMachine.types'

/**
 * Token Provider Pattern
 *
 * Instead of a module-level singleton (which causes race conditions),
 * we use a callback pattern where the Zustand store registers itself
 * as the token provider. This ensures a single source of truth.
 *
 * Flow:
 * 1. Zustand store calls registerTokenProvider() on creation
 * 2. getAccessToken() calls the registered provider
 * 3. Apollo authLink uses getAccessToken() to get current token
 *
 * CRITICAL: Fallback token for bootstrap race condition
 * On page reload, the machine starts and invokes checkAuthService BEFORE
 * the token provider is registered. To handle this, we maintain a fallback
 * token that is set during initialization and used by getAccessToken()
 * when no provider is registered yet.
 */
let tokenProvider: (() => string | null) | null = null
let tokenSetter: ((token: string | null) => void) | null = null

/**
 * Fallback token for bootstrap phase
 * Used by getAccessToken() before token provider is registered
 */
let fallbackToken: string | null = null

/**
 * Register a token provider (called by Zustand store)
 * This makes Zustand the single source of truth for tokens.
 */
export function registerTokenProvider(
  getter: () => string | null,
  setter: (token: string | null) => void
): void {
  tokenProvider = getter
  tokenSetter = setter
}

/**
 * Unregister the token provider (for cleanup)
 */
export function unregisterTokenProvider(): void {
  tokenProvider = null
  tokenSetter = null
}

/**
 * Get current access token (for Apollo authLink)
 * Delegates to the registered token provider (Zustand store)
 *
 * CRITICAL: Falls back to module-level token during bootstrap
 * This handles the race condition where checkAuthService runs
 * before the token provider is registered.
 */
export function getAccessToken(): string | null {
  if (tokenProvider) {
    return tokenProvider()
  }
  // No provider registered yet - use fallback token from initialization
  // This is critical for checkAuthService during page reload
  return fallbackToken
}

/**
 * Set the access token
 * Sets both the fallback token (for bootstrap) and delegates to registered setter
 *
 * CRITICAL: Always sets fallbackToken so getAccessToken() works during bootstrap
 * before the token provider is registered.
 *
 * @param token - The access token to set, or null to clear
 */
export function setAccessToken(token: string | null): void {
  // Always set fallback token - this is used during bootstrap
  fallbackToken = token
  // Also delegate to registered setter if available
  if (tokenSetter) {
    tokenSetter(token)
  }
}

/**
 * Default console logger
 */
const defaultLogger: AuthLogger = {
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
 * Token refresh buffer in seconds
 * Refresh 60 seconds before expiry to avoid race conditions
 */
const REFRESH_BUFFER_SECONDS = 60

/**
 * Maximum refresh attempts before giving up
 */
const MAX_REFRESH_ATTEMPTS = 3

/**
 * Transform GraphQL login response to AuthUser
 */
function transformLoginUser(loginUser: Record<string, unknown>): AuthUser {
  return {
    id: loginUser.id as string,
    email: loginUser.email as string,
    username: loginUser.username as string | undefined,
    firstName:
      (loginUser.firstName as string) ||
      (loginUser.displayName as string)?.split(' ')[0] ||
      '',
    lastName:
      (loginUser.lastName as string) ||
      (loginUser.displayName as string)?.split(' ').slice(1).join(' ') ||
      '',
    cpf: loginUser.cpf as string | undefined,
    phoneNumber: loginUser.phoneNumber as string | undefined,
    roles:
      (loginUser.roles as UserRole[]) ||
      (loginUser.role ? [loginUser.role as UserRole] : ['customer']),
    permissions: (loginUser.permissions as string[]) || [],
    emailVerified: loginUser.emailVerified as boolean,
    secondaryEmail: loginUser.secondaryEmail as string | undefined,
    secondaryEmailVerified: (loginUser.secondaryEmailVerified as boolean) || false,
    createdAt: (loginUser.createdAt as string) || new Date().toISOString(),
    updatedAt: (loginUser.updatedAt as string) || new Date().toISOString(),
  }
}

/**
 * Transform GraphQL login response to AuthTokens
 */
function transformLoginTokens(loginData: Record<string, unknown>): AuthTokens {
  return {
    accessToken: loginData.accessToken as string,
    refreshToken: (loginData.refreshToken as string) || '',
    expiresIn: loginData.expiresIn as number,
    tokenType: 'Bearer',
    sessionId: loginData.sessionId as string,
  }
}

/**
 * Create the auth machine with dependency injection
 */
export function createAuthMachine(input: AuthMachineInput): AuthMachine {
  const {
    apolloClient,
    logger = defaultLogger,
    initialTokens = null,
    initialUser = null,
    skipInitialCheck = false,
    sessionStartedAt = null,
    sessionConfig: userSessionConfig,
  } = input

  // Merge user config with defaults
  const sessionConfig: SessionConfig = {
    ...DEFAULT_SESSION_CONFIG,
    ...userSessionConfig,
  }

  // Log the initialization strategy for debugging
  logger.info('Creating auth machine', {
    hasInitialTokens: !!initialTokens?.accessToken,
    hasInitialUser: !!initialUser,
    skipInitialCheck,
    sessionStartedAt,
    absoluteTimeoutMs: sessionConfig.absoluteTimeoutMs,
    idleTimeoutMs: sessionConfig.idleTimeoutMs,
  }, 'Auth')

  return setup({
    types: {
      context: {} as AuthContext,
      events: {} as AuthEvent,
    },
    actors: {
      loginService: fromPromise<LoginOutput, { credentials: LoginCredentials }>(
        async ({ input: { credentials } }) => {
          logger.info('Login request', { email: credentials.email }, 'Auth')

          const loginInput: Record<string, string | boolean | undefined> = {
            email: credentials.email,
            cpf: credentials.cpf,
            password: credentials.password,
          }

          if (credentials.rememberMe !== undefined) {
            loginInput.rememberMe = credentials.rememberMe
          }

          const { data } = await apolloClient.mutate({
            mutation: LOGIN_MUTATION,
            variables: { input: loginInput },
          })

          if (!data?.login?.user || !data?.login?.accessToken) {
            throw new Error('Login failed: Invalid response from server')
          }

          const user = transformLoginUser(data.login.user)
          const tokens = transformLoginTokens(data.login)

          return { user, tokens }
        }
      ),

      registerService: fromPromise<RegisterResult, { data: SignupData }>(
        async ({ input: { data } }) => {
          logger.info('Register request', { email: data.email }, 'Auth')

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

          if (!result?.register?.user) {
            throw new Error('Registration failed: No user data returned')
          }

          return {
            verificationRequired: result.register.verificationRequired,
            message: result.register.message,
            userId: result.register.user.id,
            email: result.register.user.email,
          }
        }
      ),

      logoutService: fromPromise<void, { sessionId: string | undefined }>(
        async ({ input: { sessionId } }) => {
          logger.info('Logout request', { hasSessionId: !!sessionId }, 'Auth')

          // Get current access token from provider
          const accessToken = getAccessToken()
          if (accessToken && sessionId) {
            try {
              await apolloClient.mutate({
                mutation: LOGOUT_MUTATION,
                variables: { sessionId },
              })
              logger.info('Backend logout successful', {}, 'Auth')
            } catch (error) {
              logger.warn('Backend logout failed (continuing with local cleanup)', {
                error: error instanceof Error ? error.message : String(error),
              }, 'Auth')
            }
          }

          // Clear Apollo cache
          try {
            await apolloClient.clearStore()
          } catch (error) {
            logger.error('Failed to clear Apollo cache', {
              error: error instanceof Error ? error.message : String(error),
            }, 'Auth')
          }
        }
      ),

      refreshService: fromPromise<RefreshOutput, { refreshToken: string | null }>(
        async ({ input: { refreshToken } }) => {
          logger.info('Refreshing token', {}, 'Auth')

          const { data } = await apolloClient.mutate({
            mutation: REFRESH_TOKEN_MUTATION,
            variables: { refreshToken },
          })

          if (!data?.refreshToken?.accessToken) {
            throw new Error('Invalid refresh token response')
          }

          // CRITICAL: Use the NEW rotated refresh token from response, NOT the old input token
          // Backend rotates refresh tokens on each use for security
          const newRefreshToken = data.refreshToken.refreshToken || refreshToken || ''

          return {
            tokens: {
              accessToken: data.refreshToken.accessToken,
              refreshToken: newRefreshToken,
              expiresIn: data.refreshToken.expiresIn,
              tokenType: 'Bearer',
            },
          }
        }
      ),

      checkAuthService: fromPromise<CheckAuthOutput, void>(async () => {
        logger.info('📡 checkAuthService: Starting ME_QUERY', {}, 'Auth')

        try {
          const { data } = await apolloClient.query({
            query: ME_QUERY,
            fetchPolicy: 'network-only',
          })

          if (!data?.me) {
            logger.info('📡 checkAuthService: No user returned from ME_QUERY', {}, 'Auth')
            return { user: null }
          }

          const user = transformLoginUser(data.me)
          logger.info('📡 checkAuthService: User found', { userId: user.id }, 'Auth')
          return { user }
        } catch (error) {
          logger.error('📡 checkAuthService: ME_QUERY failed', {
            error: error instanceof Error ? error.message : String(error),
          }, 'Auth')
          throw error
        }
      }),

      tokenExpiryWatcher: fromPromise<void, { accessToken: string }>(
        async ({ input: { accessToken }, self }) => {
          const secondsUntilExpiry = getSecondsUntilExpiry(accessToken)
          if (secondsUntilExpiry === null) {
            logger.warn('Cannot schedule refresh - invalid token', {}, 'Auth')
            return
          }

          const refreshInSeconds = Math.max(0, secondsUntilExpiry - REFRESH_BUFFER_SECONDS)
          const refreshInMs = refreshInSeconds * 1000

          logger.info('Scheduling token refresh', {
            expiresIn: secondsUntilExpiry,
            refreshIn: refreshInSeconds,
          }, 'Auth')

          await new Promise((resolve) => setTimeout(resolve, refreshInMs))

          // Send TOKEN_EXPIRING event to parent
          // Note: In XState v5, we send events via the parent reference
          const parent = (self as AnyActorRef).system?.get('parent')
          if (parent) {
            parent.send({ type: 'TOKEN_EXPIRING' })
          }
        }
      ),
    },
    actions: {
      setAuthData: assign(({ event }) => {
        if (event.type === 'xstate.done.actor.loginService') {
          const { user, tokens } = event.output
          setAccessToken(tokens.accessToken)
          const now = Date.now()
          logger.info('Login successful', { userId: user.id }, 'Auth')
          return {
            user,
            tokens,
            error: null,
            refreshAttempts: 0,
            lastAuthenticatedAt: now,
            // WORLD-CLASS: New login starts fresh session
            sessionStartedAt: now,
            lastActivityAt: now,
          }
        }
        return {}
      }),

      setUserFromCheckAuth: assign(({ context, event }) => {
        if (event.type === 'xstate.done.actor.checkAuthService') {
          const { user } = event.output
          if (user) {
            const now = Date.now()
            logger.info('Auth check successful', { userId: user.id }, 'Auth')
            return {
              user,
              error: null,
              lastAuthenticatedAt: now,
              // WORLD-CLASS: Preserve session start if already set, else new session
              sessionStartedAt: context.sessionStartedAt ?? now,
              lastActivityAt: now,
            }
          }
        }
        return {}
      }),

      setRefreshedTokens: assign(({ context, event }) => {
        if (event.type === 'xstate.done.actor.refreshService') {
          const { tokens: newTokens } = event.output
          setAccessToken(newTokens.accessToken)
          logger.info('Token refreshed successfully', {}, 'Auth')
          return {
            tokens: {
              ...context.tokens,
              ...newTokens,
            },
            error: null,
            refreshAttempts: 0,
          }
        }
        return {}
      }),

      setAuthFromEvent: assign(({ event }) => {
        if (event.type === 'SET_AUTH') {
          setAccessToken(event.tokens.accessToken)
          const now = Date.now()
          logger.info('Auth state set directly', { userId: event.user.id }, 'Auth')
          return {
            user: event.user,
            tokens: event.tokens,
            error: null,
            refreshAttempts: 0,
            lastAuthenticatedAt: now,
            // WORLD-CLASS: OAuth/direct auth starts fresh session
            sessionStartedAt: now,
            lastActivityAt: now,
          }
        }
        return {}
      }),

      clearAuth: assign(() => {
        setAccessToken(null)
        logger.info('Auth cleared', {}, 'Auth')
        return {
          user: null,
          tokens: null,
          error: null,
          refreshAttempts: 0,
          lastAuthenticatedAt: null,
          // WORLD-CLASS: Clear all session tracking on logout
          sessionStartedAt: null,
          lastActivityAt: null,
        }
      }),

      // WORLD-CLASS SESSION HANDLING: Update last activity timestamp
      updateActivity: assign(() => ({
        lastActivityAt: Date.now(),
      })),

      setError: assign(({ event }) => {
        let error: AuthError

        if (
          event.type === 'xstate.error.actor.loginService' ||
          event.type === 'xstate.error.actor.registerService' ||
          event.type === 'xstate.error.actor.refreshService' ||
          event.type === 'xstate.error.actor.checkAuthService'
        ) {
          const apolloError = event.error as ApolloError
          let code: AuthError['code'] = 'UNKNOWN'
          let message = 'An error occurred'

          const gqlErrors = apolloError?.graphQLErrors
          if (gqlErrors && gqlErrors.length > 0) {
            const gqlError = gqlErrors[0]
            const errorCode = gqlError?.extensions?.code as string | undefined
            message = gqlError?.message || message

            if (errorCode === 'UNAUTHENTICATED' || errorCode === 'FORBIDDEN') {
              code = 'UNAUTHORIZED'
            } else if (message.toLowerCase().includes('password')) {
              code = 'INVALID_CREDENTIALS'
            } else if (message.toLowerCase().includes('email')) {
              code = 'INVALID_CREDENTIALS'
            } else if (message.toLowerCase().includes('cpf')) {
              code = 'INVALID_CREDENTIALS'
            } else if (message.toLowerCase().includes('token')) {
              code = 'TOKEN_INVALID'
            }
          } else if (apolloError?.networkError) {
            code = 'NETWORK_ERROR'
            message = 'Network error. Please check your connection.'
          }

          error = { message, code, originalError: event.error }
          logger.error('Auth error', { code, message }, 'Auth')
        } else {
          error = createAuthError('Unknown error')
        }

        return { error }
      }),

      clearError: assign(() => ({
        error: null,
      })),

      incrementRefreshAttempts: assign(({ context }) => ({
        refreshAttempts: context.refreshAttempts + 1,
      })),

      logForceLogout: () => {
        logger.info('Force logout executed', {}, 'Auth')
      },
    },
    guards: {
      hasAuthData: ({ context }) => context.user !== null && context.tokens !== null,

      // GRACEFUL RECOVERY: Check if we got a valid user from ME_QUERY
      hasUser: ({ event }) => {
        if (event.type === 'xstate.done.actor.checkAuthService') {
          return event.output.user !== null
        }
        return false
      },

      // Check if we have BOTH user from ME_QUERY AND tokens in context
      // CRITICAL: Only transition to authenticated if we can actually make authenticated requests
      hasUserAndTokens: ({ context, event }) => {
        if (event.type === 'xstate.done.actor.checkAuthService') {
          const hasUser = event.output.user !== null
          const hasValidTokens = context.tokens?.accessToken != null && context.tokens.accessToken !== ''
          logger.info('Guard hasUserAndTokens', { hasUser, hasValidTokens }, 'Auth')
          return hasUser && hasValidTokens
        }
        return false
      },

      // Check if we got user from ME_QUERY but DON'T have tokens
      // This triggers a refresh to get tokens before going to authenticated
      hasUserButNoTokens: ({ context, event }) => {
        if (event.type === 'xstate.done.actor.checkAuthService') {
          const hasUser = event.output.user !== null
          const hasValidTokens = context.tokens?.accessToken != null && context.tokens.accessToken !== ''
          logger.info('Guard hasUserButNoTokens', { hasUser, hasValidTokens: !hasValidTokens }, 'Auth')
          return hasUser && !hasValidTokens
        }
        return false
      },

      // Legacy guard (kept for compatibility)
      hasNoUser: ({ event }) => {
        if (event.type === 'xstate.done.actor.checkAuthService') {
          return event.output.user === null
        }
        return false
      },

      // GRACEFUL RECOVERY: No user returned but we have tokens - should try refresh
      // Limited to 1 retry attempt to prevent infinite loops
      hasNoUserButHasTokens: ({ context, event }) => {
        if (event.type === 'xstate.done.actor.checkAuthService') {
          const noUser = event.output.user === null
          const hasTokens = context.tokens?.refreshToken != null && context.tokens.refreshToken !== ''
          const canRetry = context.refreshAttempts < 1 // Only try once
          return noUser && hasTokens && canRetry
        }
        return false
      },

      // GRACEFUL RECOVERY: Error occurred but we have tokens to try refresh
      // Limited to 1 retry attempt to prevent infinite loops
      hasTokensForRetry: ({ context, event }) => {
        // Only on checkAuthService errors (not retryRefreshService to prevent loops)
        if (event.type === 'xstate.error.actor.checkAuthService') {
          const apolloError = event.error as ApolloError
          const isAuthError = apolloError?.graphQLErrors?.some(
            (e) => e.extensions?.code === 'UNAUTHENTICATED'
          ) ?? false
          const hasTokens = context.tokens?.refreshToken != null && context.tokens.refreshToken !== ''
          const canRetry = context.refreshAttempts < 1 // Only try once
          // Only retry if it's an auth error AND we have refresh token AND haven't retried yet
          return isAuthError && hasTokens && canRetry
        }
        return false
      },

      canRetryRefresh: ({ context }) => context.refreshAttempts < MAX_REFRESH_ATTEMPTS,

      // APOLLO INTEGRATION: Allow refresh only if we haven't exceeded max attempts
      // Note: XState v5 naturally prevents transitioning to the same state
      // so APOLLO_AUTH_ERROR when already in refreshingToken is a no-op
      notAlreadyRefreshing: ({ context }) => {
        return context.refreshAttempts < MAX_REFRESH_ATTEMPTS
      },

      isAuthError: ({ event }) => {
        // Check for error events from auth-related actors
        // Uses string check to handle both refreshService and retryRefreshService
        const eventType = event.type as string
        if (
          eventType === 'xstate.error.actor.checkAuthService' ||
          eventType.startsWith('xstate.error.actor.refresh') ||
          eventType.startsWith('xstate.error.actor.retryRefresh')
        ) {
          const apolloError = (event as { error?: ApolloError }).error
          return apolloError?.graphQLErrors?.some(
            (e) =>
              e.extensions?.code === 'UNAUTHENTICATED' || e.extensions?.code === 'FORBIDDEN'
          ) ?? false
        }
        return false
      },
    },
  }).createMachine({
    id: 'auth',
    /**
     * DYNAMIC INITIAL STATE based on restored session
     *
     * skipInitialCheck=true: Start directly in 'authenticated' state
     *   - Used when we have valid (non-expired) tokens AND user from localStorage
     *   - Prevents unnecessary network request and ensures instant auth state
     *   - The tokenExpiryWatcher will still run and refresh when needed
     *
     * skipInitialCheck=false: Start in 'initializing' -> 'checkingAuth' flow
     *   - Used on fresh load or when tokens are expired/missing
     *   - Verifies session with backend via ME_QUERY
     */
    initial: skipInitialCheck ? 'authenticated' : 'initializing',
    context: {
      // CRITICAL: Use initialUser if provided (restored from localStorage)
      // When skipInitialCheck=true, we trust this data for immediate auth state
      user: initialUser,
      // CRITICAL: Use initialTokens if provided (restored from localStorage)
      // This ensures tokens are available in context when checkAuth succeeds
      tokens: initialTokens,
      error: null,
      refreshAttempts: 0,
      // Set lastAuthenticatedAt if we have restored user (for session age tracking)
      lastAuthenticatedAt: initialUser ? Date.now() : null,
      // WORLD-CLASS SESSION HANDLING: Session start time for absolute timeout
      // Preserved across page reloads to enforce max session duration
      sessionStartedAt: sessionStartedAt ?? (initialUser ? Date.now() : null),
      // WORLD-CLASS SESSION HANDLING: Last activity for idle timeout
      // Reset on user interactions, used to detect inactive sessions
      lastActivityAt: initialUser ? Date.now() : null,
    },
    states: {
      /**
       * Initializing state - immediately transitions to checkingAuth
       * This ensures isLoading=true from the start until auth is verified
       */
      initializing: {
        always: {
          target: 'checkingAuth',
        },
      },

      idle: {
        on: {
          LOGIN: {
            target: 'loggingIn',
          },
          REGISTER: {
            target: 'registering',
          },
          CHECK_AUTH: {
            target: 'checkingAuth',
          },
          SET_AUTH: {
            target: 'authenticated',
            actions: ['setAuthFromEvent'],
          },
        },
      },

      checkingAuth: {
        invoke: {
          id: 'checkAuthService',
          src: 'checkAuthService',
          onDone: [
            // Success - user returned AND we have valid tokens in context
            // CRITICAL: Only go to authenticated if we have BOTH user AND tokens
            // Otherwise Apollo will fail on subsequent requests (no Authorization header)
            {
              target: 'authenticated',
              guard: 'hasUserAndTokens',
              actions: ['setUserFromCheckAuth'],
            },
            // User returned but NO tokens in context - need to refresh to get tokens
            // This happens on page reload when:
            // 1. localStorage tokens were cleared or expired
            // 2. ME_QUERY succeeded (via httpOnly cookie) but we have no access token
            {
              target: 'retryingAuthWithRefresh',
              guard: 'hasUserButNoTokens',
              actions: ['setUserFromCheckAuth'],
            },
            // GRACEFUL RECOVERY: No user returned but we have tokens - try refresh first
            // This handles the case where the access token expired between validation and ME_QUERY
            {
              target: 'retryingAuthWithRefresh',
              guard: 'hasNoUserButHasTokens',
            },
            // No user and no tokens - truly logged out
            {
              target: 'idle',
              actions: ['clearAuth'],
            },
          ],
          onError: [
            // GRACEFUL RECOVERY: Auth error but we have tokens - try refresh first
            // This handles UNAUTHENTICATED errors that might be due to expired token
            {
              target: 'retryingAuthWithRefresh',
              guard: 'hasTokensForRetry',
            },
            // Auth error with no tokens - clear and go idle
            {
              target: 'idle',
              guard: 'isAuthError',
              actions: ['clearAuth'],
            },
            // Other errors - set error and go idle
            {
              target: 'idle',
              actions: ['setError'],
            },
          ],
        },
      },

      /**
       * GRACEFUL RECOVERY STATE
       *
       * When checkingAuth fails but we have stored tokens, attempt to refresh
       * before giving up. This handles the "login then immediate logout" bug
       * where the access token expires between validation and ME_QUERY.
       *
       * Limited to 1 attempt via refreshAttempts counter to prevent infinite loops.
       */
      retryingAuthWithRefresh: {
        entry: 'incrementRefreshAttempts',
        invoke: {
          id: 'retryRefreshService',
          src: 'refreshService',
          input: ({ context }) => ({
            refreshToken: context.tokens?.refreshToken || '',
          }),
          onDone: {
            // Refresh succeeded - retry checkAuth with new token
            target: 'checkingAuth',
            actions: ['setRefreshedTokens'],
          },
          onError: {
            // Refresh failed - now truly logged out
            target: 'idle',
            actions: ['clearAuth'],
          },
        },
      },

      loggingIn: {
        invoke: {
          id: 'loginService',
          src: 'loginService',
          input: ({ event }) => {
            if (event.type === 'LOGIN') {
              return { credentials: event.credentials }
            }
            throw new Error('Invalid event for loggingIn state')
          },
          onDone: {
            target: 'authenticated',
            actions: ['setAuthData'],
          },
          onError: {
            target: 'error',
            actions: ['setError'],
          },
        },
      },

      registering: {
        invoke: {
          id: 'registerService',
          src: 'registerService',
          input: ({ event }) => {
            if (event.type === 'REGISTER') {
              return { data: event.data }
            }
            throw new Error('Invalid event for registering state')
          },
          onDone: {
            target: 'idle',
            // Registration doesn't log in - user needs to verify email
          },
          onError: {
            target: 'error',
            actions: ['setError'],
          },
        },
      },

      authenticated: {
        /**
         * CRITICAL ARCHITECTURE: refreshingToken is a NESTED state under authenticated
         *
         * This ensures that during token refresh:
         * - isAuthenticated remains TRUE (parent state is 'authenticated')
         * - isRefreshing is TRUE (nested state is 'refreshingToken')
         * - isLoading is FALSE (not in loggingIn/loggingOut/checkingAuth)
         *
         * This prevents UI flicker during background token refresh.
         */
        initial: 'idle',
        invoke: {
          id: 'tokenExpiryWatcher',
          src: 'tokenExpiryWatcher',
          input: ({ context }) => ({
            accessToken: context.tokens?.accessToken || '',
          }),
        },
        states: {
          idle: {
            on: {
              TOKEN_EXPIRING: {
                target: 'refreshingToken',
              },
              REFRESH_TOKEN: {
                target: 'refreshingToken',
              },
            },
          },
          refreshingToken: {
            entry: ['incrementRefreshAttempts'],
            invoke: {
              id: 'refreshService',
              src: 'refreshService',
              input: ({ context }) => ({
                refreshToken:
                  context.tokens?.refreshToken && context.tokens.refreshToken.trim() !== ''
                    ? context.tokens.refreshToken
                    : null,
              }),
              onDone: {
                target: 'idle',
                actions: ['setRefreshedTokens'],
              },
              onError: [
                {
                  target: 'refreshingToken',
                  guard: 'canRetryRefresh',
                },
                {
                  // CRITICAL: On refresh failure after max retries, go to root idle (logout)
                  target: '#auth.idle',
                  actions: ['clearAuth', 'setError'],
                },
              ],
            },
          },
        },
        on: {
          LOGOUT: {
            target: 'loggingOut',
          },
          FORCE_LOGOUT: {
            target: 'idle',
            actions: ['clearAuth', 'logForceLogout'],
          },
          CLEAR_ERROR: {
            actions: ['clearError'],
          },
          // APOLLO INTEGRATION: Apollo error link reports auth errors here
          // Machine decides to refresh token (if not already refreshing)
          APOLLO_AUTH_ERROR: {
            target: '.refreshingToken',
            guard: 'notAlreadyRefreshing',
          },
          // WORLD-CLASS SESSION HANDLING: User activity tracking
          USER_ACTIVITY: {
            actions: ['updateActivity'],
          },
          // WORLD-CLASS SESSION HANDLING: Timeout events
          IDLE_TIMEOUT: {
            target: '#auth.idle',
            actions: ['clearAuth'],
          },
          ABSOLUTE_TIMEOUT: {
            target: '#auth.idle',
            actions: ['clearAuth'],
          },
          // WORLD-CLASS SESSION HANDLING: User extends session (dismisses warning)
          EXTEND_SESSION: {
            actions: ['updateActivity'],
          },
        },
      },

      loggingOut: {
        invoke: {
          id: 'logoutService',
          src: 'logoutService',
          input: ({ context }) => ({
            sessionId: context.tokens?.sessionId,
          }),
          onDone: {
            target: 'idle',
            actions: ['clearAuth'],
          },
          onError: {
            target: 'idle',
            actions: ['clearAuth'],
          },
        },
      },

      error: {
        on: {
          LOGIN: {
            target: 'loggingIn',
          },
          REGISTER: {
            target: 'registering',
          },
          CLEAR_ERROR: {
            target: 'idle',
            actions: ['clearError'],
          },
        },
      },
    },
  })
}

/**
 * Type for the created auth machine
 */
export type AuthMachine = ReturnType<typeof createAuthMachine>

/**
 * Export types
 */
export type { AuthContext, AuthEvent, AuthLogger, AuthMachineInput } from './authMachine.types'
