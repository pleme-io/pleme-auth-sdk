/**
 * XState Auth Machine Tests
 *
 * Tests for the authentication state machine that coordinates all auth flows.
 * Critical regressions tested:
 * 1. Machine starts in 'initializing' state (auto CHECK_AUTH)
 * 2. refreshingToken is NESTED under authenticated (no UI flicker)
 * 3. isAuthenticated stays TRUE during background refresh
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { createActor, type AnyActorRef } from 'xstate'
import { createAuthMachine, registerTokenProvider, unregisterTokenProvider } from '../machines/authMachine'
import type { ApolloClient, NormalizedCacheObject } from '@apollo/client'

// Helper to create valid JWT token
function createMockJWT(payload: {
  sub: string
  exp: number
  iat: number
  roles?: string[]
}): string {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
  const payloadStr = btoa(JSON.stringify(payload))
  const signature = btoa('mock-signature')
  return `${header}.${payloadStr}.${signature}`
}

// Helper to create future timestamp
function futureTimestamp(seconds: number): number {
  return Math.floor(Date.now() / 1000) + seconds
}

describe('AuthMachine', () => {
  let mockApolloClient: Partial<ApolloClient<NormalizedCacheObject>>
  let mockLogger: {
    info: ReturnType<typeof vi.fn>
    warn: ReturnType<typeof vi.fn>
    error: ReturnType<typeof vi.fn>
    debug: ReturnType<typeof vi.fn>
  }

  beforeEach(() => {
    vi.useFakeTimers()

    mockApolloClient = {
      mutate: vi.fn(),
      query: vi.fn(),
      clearStore: vi.fn().mockResolvedValue(undefined),
    }

    mockLogger = {
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
      debug: vi.fn(),
    }

    // Register token provider
    registerTokenProvider(
      () => null,
      () => {}
    )
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.clearAllMocks()
    unregisterTokenProvider()
  })

  describe('Initial State - Auto CHECK_AUTH (Regression Test)', () => {
    /**
     * CRITICAL FIX: The machine MUST start in 'initializing' state which
     * immediately transitions to 'checkingAuth'. This ensures:
     * - isLoading=true from the start (no flash of unauthenticated UI)
     * - Auth status is checked automatically on app load
     * - User menu shows correctly for authenticated users
     */

    it('should start in initializing/checkingAuth state', () => {
      const machine = createAuthMachine({
        apolloClient: mockApolloClient as ApolloClient<NormalizedCacheObject>,
        logger: mockLogger,
      })

      const actor = createActor(machine)
      const initialSnapshot = actor.getSnapshot()

      // Machine starts in 'initializing' which immediately transitions to 'checkingAuth'
      // via the 'always' transition. XState evaluates 'always' transitions synchronously,
      // so even before start() the snapshot shows 'checkingAuth'.
      // The important thing is that the machine does NOT start in 'idle'.
      expect(initialSnapshot.value).toBe('checkingAuth')
    })

    it('should immediately transition from initializing to checkingAuth', async () => {
      // Mock successful ME query (user is authenticated)
      vi.mocked(mockApolloClient.query!).mockResolvedValue({
        data: {
          me: {
            id: 'user-123',
            email: 'test@example.com',
            displayName: 'Test User',
            roles: ['customer'],
            permissions: [],
            emailVerified: true,
          },
        },
      })

      const machine = createAuthMachine({
        apolloClient: mockApolloClient as ApolloClient<NormalizedCacheObject>,
        logger: mockLogger,
      })

      const actor = createActor(machine)
      actor.start()

      // After starting, should be in checkingAuth (immediate transition from initializing)
      // The 'always' transition happens synchronously
      const snapshot = actor.getSnapshot()
      expect(snapshot.value).toBe('checkingAuth')

      actor.stop()
    })

    it('should transition to authenticated after successful checkAuth', async () => {
      vi.mocked(mockApolloClient.query!).mockResolvedValue({
        data: {
          me: {
            id: 'user-123',
            email: 'test@example.com',
            displayName: 'Test User',
            roles: ['customer'],
            permissions: [],
            emailVerified: true,
          },
        },
      })

      const machine = createAuthMachine({
        apolloClient: mockApolloClient as ApolloClient<NormalizedCacheObject>,
        logger: mockLogger,
      })

      const actor = createActor(machine)

      let finalState: string | undefined
      actor.subscribe((snapshot) => {
        finalState = JSON.stringify(snapshot.value)
      })

      actor.start()

      // Wait for async checkAuth to complete
      await vi.runAllTimersAsync()

      expect(finalState).toContain('authenticated')

      actor.stop()
    })

    it('should transition to idle when no user (not authenticated)', async () => {
      vi.mocked(mockApolloClient.query!).mockResolvedValue({
        data: {
          me: null,
        },
      })

      const machine = createAuthMachine({
        apolloClient: mockApolloClient as ApolloClient<NormalizedCacheObject>,
        logger: mockLogger,
      })

      const actor = createActor(machine)

      let finalState: string | undefined
      actor.subscribe((snapshot) => {
        finalState = JSON.stringify(snapshot.value)
      })

      actor.start()

      await vi.runAllTimersAsync()

      expect(finalState).toBe('"idle"')

      actor.stop()
    })

    it('should transition to idle on checkAuth network error', async () => {
      vi.mocked(mockApolloClient.query!).mockRejectedValue(new Error('Network error'))

      const machine = createAuthMachine({
        apolloClient: mockApolloClient as ApolloClient<NormalizedCacheObject>,
        logger: mockLogger,
      })

      const actor = createActor(machine)

      let finalState: string | undefined
      actor.subscribe((snapshot) => {
        finalState = JSON.stringify(snapshot.value)
      })

      actor.start()

      await vi.runAllTimersAsync()

      expect(finalState).toBe('"idle"')

      actor.stop()
    })
  })

  describe('Nested refreshingToken State (Regression Test)', () => {
    /**
     * CRITICAL FIX: refreshingToken MUST be a nested state under 'authenticated'.
     * This ensures:
     * - isAuthenticated stays TRUE during background refresh
     * - isLoading stays FALSE during background refresh
     * - isRefreshing is TRUE only during refresh
     * - NO UI FLICKER during token refresh
     */

    it('should have refreshingToken as nested state under authenticated', async () => {
      // First, get to authenticated state
      vi.mocked(mockApolloClient.query!).mockResolvedValue({
        data: {
          me: {
            id: 'user-123',
            email: 'test@example.com',
            displayName: 'Test User',
            roles: ['customer'],
            permissions: [],
            emailVerified: true,
          },
        },
      })

      const machine = createAuthMachine({
        apolloClient: mockApolloClient as ApolloClient<NormalizedCacheObject>,
        logger: mockLogger,
      })

      const actor = createActor(machine)
      actor.start()

      await vi.runAllTimersAsync()

      // Set up tokens and send REFRESH_TOKEN event
      // Mock the refresh to be slow so we can observe the state
      vi.mocked(mockApolloClient.mutate!).mockImplementation(
        () =>
          new Promise((resolve) => {
            setTimeout(() => {
              resolve({
                data: {
                  refreshToken: {
                    accessToken: createMockJWT({
                      sub: 'user-123',
                      exp: futureTimestamp(3600),
                      iat: Math.floor(Date.now() / 1000),
                    }),
                    expiresIn: 3600,
                  },
                },
              })
            }, 1000)
          })
      )

      // Set context with tokens
      actor.send({
        type: 'SET_AUTH',
        user: {
          id: 'user-123',
          email: 'test@example.com',
          firstName: 'Test',
          lastName: 'User',
          roles: ['customer'],
          permissions: [],
        },
        tokens: {
          accessToken: createMockJWT({
            sub: 'user-123',
            exp: futureTimestamp(300), // Short expiry
            iat: Math.floor(Date.now() / 1000),
          }),
          refreshToken: 'valid-refresh-token',
          expiresIn: 300,
          tokenType: 'Bearer',
        },
      })

      await vi.runAllTimersAsync()

      // Trigger refresh
      actor.send({ type: 'REFRESH_TOKEN' })

      // Check state immediately - should be { authenticated: 'refreshingToken' }
      const snapshot = actor.getSnapshot()

      // CRITICAL: Must be nested state
      expect(snapshot.matches('authenticated')).toBe(true)
      expect(snapshot.matches({ authenticated: 'refreshingToken' })).toBe(true)

      // isAuthenticated should still be true (parent state is authenticated)
      expect(snapshot.matches('authenticated')).toBe(true)

      actor.stop()
    })

    it('should stay authenticated during token refresh', async () => {
      vi.mocked(mockApolloClient.query!).mockResolvedValue({
        data: {
          me: {
            id: 'user-123',
            email: 'test@example.com',
            displayName: 'Test User',
            roles: ['customer'],
            permissions: [],
            emailVerified: true,
          },
        },
      })

      // Slow refresh mutation
      vi.mocked(mockApolloClient.mutate!).mockImplementation(
        () =>
          new Promise((resolve) => {
            setTimeout(() => {
              resolve({
                data: {
                  refreshToken: {
                    accessToken: createMockJWT({
                      sub: 'user-123',
                      exp: futureTimestamp(3600),
                      iat: Math.floor(Date.now() / 1000),
                    }),
                    expiresIn: 3600,
                  },
                },
              })
            }, 1000)
          })
      )

      const machine = createAuthMachine({
        apolloClient: mockApolloClient as ApolloClient<NormalizedCacheObject>,
        logger: mockLogger,
      })

      const actor = createActor(machine)
      const stateHistory: boolean[] = []

      actor.subscribe((snapshot) => {
        stateHistory.push(snapshot.matches('authenticated'))
      })

      actor.start()
      await vi.runAllTimersAsync()

      // Set auth and trigger refresh
      actor.send({
        type: 'SET_AUTH',
        user: {
          id: 'user-123',
          email: 'test@example.com',
          firstName: 'Test',
          lastName: 'User',
          roles: ['customer'],
          permissions: [],
        },
        tokens: {
          accessToken: createMockJWT({
            sub: 'user-123',
            exp: futureTimestamp(300),
            iat: Math.floor(Date.now() / 1000),
          }),
          refreshToken: 'valid-refresh-token',
          expiresIn: 300,
          tokenType: 'Bearer',
        },
      })

      await vi.advanceTimersByTimeAsync(100)
      actor.send({ type: 'REFRESH_TOKEN' })

      // During refresh
      await vi.advanceTimersByTimeAsync(500)
      expect(actor.getSnapshot().matches('authenticated')).toBe(true)

      // After refresh completes
      await vi.advanceTimersByTimeAsync(1000)
      expect(actor.getSnapshot().matches('authenticated')).toBe(true)

      // CRITICAL: isAuthenticated should NEVER have been false during refresh
      // Filter to only states after we became authenticated
      const authenticatedStates = stateHistory.slice(stateHistory.indexOf(true))
      expect(authenticatedStates.every((s) => s === true)).toBe(true)

      actor.stop()
    })
  })

  describe('Login Flow', () => {
    it('should transition from idle to loggingIn on LOGIN event', async () => {
      vi.mocked(mockApolloClient.query!).mockResolvedValue({ data: { me: null } })

      const machine = createAuthMachine({
        apolloClient: mockApolloClient as ApolloClient<NormalizedCacheObject>,
        logger: mockLogger,
      })

      const actor = createActor(machine)
      actor.start()

      // Wait for initial checkAuth to complete
      await vi.runAllTimersAsync()
      expect(actor.getSnapshot().value).toBe('idle')

      // Start slow login
      vi.mocked(mockApolloClient.mutate!).mockImplementation(
        () =>
          new Promise((resolve) => {
            setTimeout(() => {
              resolve({
                data: {
                  login: {
                    user: {
                      id: 'user-123',
                      email: 'test@example.com',
                      displayName: 'Test User',
                      roles: ['customer'],
                      permissions: [],
                      emailVerified: true,
                    },
                    accessToken: createMockJWT({
                      sub: 'user-123',
                      exp: futureTimestamp(3600),
                      iat: Math.floor(Date.now() / 1000),
                    }),
                    refreshToken: 'refresh-token',
                    expiresIn: 3600,
                    sessionId: 'session-123',
                  },
                },
              })
            }, 1000)
          })
      )

      actor.send({
        type: 'LOGIN',
        credentials: {
          email: 'test@example.com',
          cpf: '12345678900',
          password: 'password123',
        },
      })

      expect(actor.getSnapshot().value).toBe('loggingIn')

      await vi.runAllTimersAsync()

      expect(actor.getSnapshot().matches('authenticated')).toBe(true)

      actor.stop()
    })

    it('should transition to error state on login failure', async () => {
      vi.mocked(mockApolloClient.query!).mockResolvedValue({ data: { me: null } })

      const machine = createAuthMachine({
        apolloClient: mockApolloClient as ApolloClient<NormalizedCacheObject>,
        logger: mockLogger,
      })

      const actor = createActor(machine)
      actor.start()

      await vi.runAllTimersAsync()

      vi.mocked(mockApolloClient.mutate!).mockRejectedValue(new Error('Invalid credentials'))

      actor.send({
        type: 'LOGIN',
        credentials: {
          email: 'test@example.com',
          cpf: '12345678900',
          password: 'wrong-password',
        },
      })

      await vi.runAllTimersAsync()

      expect(actor.getSnapshot().value).toBe('error')
      expect(actor.getSnapshot().context.error).not.toBeNull()

      actor.stop()
    })
  })

  describe('Logout Flow', () => {
    it('should transition to loggingOut then idle on LOGOUT', async () => {
      vi.mocked(mockApolloClient.query!).mockResolvedValue({
        data: {
          me: {
            id: 'user-123',
            email: 'test@example.com',
            displayName: 'Test User',
            roles: ['customer'],
            permissions: [],
            emailVerified: true,
          },
        },
      })

      const machine = createAuthMachine({
        apolloClient: mockApolloClient as ApolloClient<NormalizedCacheObject>,
        logger: mockLogger,
      })

      const actor = createActor(machine)
      actor.start()

      await vi.runAllTimersAsync()
      expect(actor.getSnapshot().matches('authenticated')).toBe(true)

      // Mock logout
      vi.mocked(mockApolloClient.mutate!).mockResolvedValue({ data: { logout: true } })

      actor.send({ type: 'LOGOUT' })

      await vi.runAllTimersAsync()

      expect(actor.getSnapshot().value).toBe('idle')
      expect(actor.getSnapshot().context.user).toBeNull()
      expect(actor.getSnapshot().context.tokens).toBeNull()

      actor.stop()
    })

    it('should clear auth immediately on FORCE_LOGOUT', async () => {
      vi.mocked(mockApolloClient.query!).mockResolvedValue({
        data: {
          me: {
            id: 'user-123',
            email: 'test@example.com',
            displayName: 'Test User',
            roles: ['customer'],
            permissions: [],
            emailVerified: true,
          },
        },
      })

      const machine = createAuthMachine({
        apolloClient: mockApolloClient as ApolloClient<NormalizedCacheObject>,
        logger: mockLogger,
      })

      const actor = createActor(machine)
      actor.start()

      await vi.runAllTimersAsync()

      actor.send({ type: 'FORCE_LOGOUT' })

      // Force logout should be immediate (no async operation)
      expect(actor.getSnapshot().value).toBe('idle')
      expect(actor.getSnapshot().context.user).toBeNull()

      actor.stop()
    })
  })

  describe('State Value Types', () => {
    it('should include initializing in valid state values', () => {
      const machine = createAuthMachine({
        apolloClient: mockApolloClient as ApolloClient<NormalizedCacheObject>,
        logger: mockLogger,
      })

      // Get the machine definition
      const stateKeys = Object.keys(machine.config.states || {})

      expect(stateKeys).toContain('initializing')
      expect(stateKeys).toContain('idle')
      expect(stateKeys).toContain('checkingAuth')
      expect(stateKeys).toContain('authenticated')
      expect(stateKeys).toContain('loggingIn')
      expect(stateKeys).toContain('loggingOut')
      expect(stateKeys).toContain('error')
    })
  })
})
