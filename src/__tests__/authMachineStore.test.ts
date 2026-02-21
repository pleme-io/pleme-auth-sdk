/**
 * XState + Zustand Auth Machine Store Tests
 *
 * Tests for the unified auth store that derives Zustand state from XState machine.
 * Critical regressions tested:
 * 1. isLoading starts TRUE (machine starts in initializing state)
 * 2. isAuthenticated stays TRUE during background refresh
 * 3. isRefreshing is separate from isLoading
 * 4. hasHydrated is always TRUE (no Zustand persistence)
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { act } from '@testing-library/react'
import { createAuthMachineStore, type AuthMachineStoreConfig } from '../store/authMachineStore'
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

function futureTimestamp(seconds: number): number {
  return Math.floor(Date.now() / 1000) + seconds
}

describe('createAuthMachineStore', () => {
  let mockApolloClient: Partial<ApolloClient<NormalizedCacheObject>>
  let mockLogger: AuthMachineStoreConfig['logger']

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
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.clearAllMocks()
  })

  describe('Initial State (Regression Tests)', () => {
    /**
     * CRITICAL FIX: Store must start with isLoading=true because the XState
     * machine starts in 'initializing' state which transitions to 'checkingAuth'.
     * This prevents flash of "Entrar" buttons before auth check completes.
     */

    it('should start with isLoading=true', () => {
      // Mock slow checkAuth so we can observe initial state
      vi.mocked(mockApolloClient.query!).mockImplementation(
        () => new Promise(() => {}) // Never resolves
      )

      const store = createAuthMachineStore({
        apolloClient: mockApolloClient as ApolloClient<NormalizedCacheObject>,
        logger: mockLogger,
      })

      const state = store.getState()

      // CRITICAL: isLoading must be true initially
      expect(state.isLoading).toBe(true)
    })

    it('should have hasHydrated=true (no Zustand persistence)', () => {
      vi.mocked(mockApolloClient.query!).mockImplementation(
        () => new Promise(() => {})
      )

      const store = createAuthMachineStore({
        apolloClient: mockApolloClient as ApolloClient<NormalizedCacheObject>,
        logger: mockLogger,
      })

      // hasHydrated should always be true (no Zustand persist middleware)
      expect(store.getState().hasHydrated).toBe(true)
    })

    it('should start with isAuthenticated=false', () => {
      vi.mocked(mockApolloClient.query!).mockImplementation(
        () => new Promise(() => {})
      )

      const store = createAuthMachineStore({
        apolloClient: mockApolloClient as ApolloClient<NormalizedCacheObject>,
        logger: mockLogger,
      })

      expect(store.getState().isAuthenticated).toBe(false)
    })

    it('should start with machineState="initializing"', () => {
      vi.mocked(mockApolloClient.query!).mockImplementation(
        () => new Promise(() => {})
      )

      const store = createAuthMachineStore({
        apolloClient: mockApolloClient as ApolloClient<NormalizedCacheObject>,
        logger: mockLogger,
      })

      // Initial machine state should be "initializing"
      expect(store.getState().machineState).toBe('"initializing"')
    })
  })

  describe('Auto Check Auth on Init (Regression Test)', () => {
    it('should automatically check auth when store is created', async () => {
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

      const store = createAuthMachineStore({
        apolloClient: mockApolloClient as ApolloClient<NormalizedCacheObject>,
        logger: mockLogger,
      })

      // Wait for checkAuth to complete
      await vi.runAllTimersAsync()

      const state = store.getState()
      expect(state.isAuthenticated).toBe(true)
      expect(state.isLoading).toBe(false)
      expect(state.user?.email).toBe('test@example.com')
    })

    it('should set isLoading=false and isAuthenticated=false when no user', async () => {
      vi.mocked(mockApolloClient.query!).mockResolvedValue({
        data: { me: null },
      })

      const store = createAuthMachineStore({
        apolloClient: mockApolloClient as ApolloClient<NormalizedCacheObject>,
        logger: mockLogger,
      })

      await vi.runAllTimersAsync()

      const state = store.getState()
      expect(state.isAuthenticated).toBe(false)
      expect(state.isLoading).toBe(false)
      expect(state.user).toBeNull()
    })
  })

  describe('isLoading vs isRefreshing Separation (Regression Test)', () => {
    /**
     * CRITICAL FIX: isLoading and isRefreshing must be separate:
     * - isLoading = true for: initializing, loggingIn, loggingOut, checkingAuth, registering
     * - isRefreshing = true for: authenticated.refreshingToken (nested state)
     *
     * During background refresh:
     * - isLoading = FALSE
     * - isRefreshing = TRUE
     * - isAuthenticated = TRUE (NO FLICKER)
     */

    it('should have isLoading=true during loggingIn', async () => {
      vi.mocked(mockApolloClient.query!).mockResolvedValue({ data: { me: null } })

      const store = createAuthMachineStore({
        apolloClient: mockApolloClient as ApolloClient<NormalizedCacheObject>,
        logger: mockLogger,
      })

      await vi.runAllTimersAsync() // Complete initial checkAuth

      // Mock slow login
      vi.mocked(mockApolloClient.mutate!).mockImplementation(
        () => new Promise(() => {}) // Never resolves
      )

      store.getState().login({
        email: 'test@example.com',
        cpf: '12345678900',
        password: 'password123',
      })

      await vi.advanceTimersByTimeAsync(100)

      expect(store.getState().isLoading).toBe(true)
      expect(store.getState().isRefreshing).toBe(false)
    })

    it('should have isRefreshing=true but isLoading=false during token refresh', async () => {
      // Start authenticated
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

      const store = createAuthMachineStore({
        apolloClient: mockApolloClient as ApolloClient<NormalizedCacheObject>,
        logger: mockLogger,
      })

      await vi.runAllTimersAsync()
      expect(store.getState().isAuthenticated).toBe(true)

      // Mock slow refresh
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
            }, 5000)
          })
      )

      // Trigger refresh
      store.getState().refreshToken()

      await vi.advanceTimersByTimeAsync(100)

      // CRITICAL: During refresh
      const state = store.getState()
      expect(state.isRefreshing).toBe(true)
      expect(state.isLoading).toBe(false) // NOT loading!
      expect(state.isAuthenticated).toBe(true) // Still authenticated!
    })

    it('should maintain isAuthenticated=true throughout refresh cycle', async () => {
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

      const store = createAuthMachineStore({
        apolloClient: mockApolloClient as ApolloClient<NormalizedCacheObject>,
        logger: mockLogger,
      })

      await vi.runAllTimersAsync()

      const isAuthenticatedHistory: boolean[] = []
      store.subscribe((state) => {
        isAuthenticatedHistory.push(state.isAuthenticated)
      })

      // Mock refresh
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

      store.getState().refreshToken()

      // Before refresh completes
      await vi.advanceTimersByTimeAsync(500)
      expect(store.getState().isAuthenticated).toBe(true)

      // After refresh completes
      await vi.advanceTimersByTimeAsync(1000)
      expect(store.getState().isAuthenticated).toBe(true)

      // CRITICAL: isAuthenticated should NEVER have been false after initial auth
      const afterAuth = isAuthenticatedHistory.slice(isAuthenticatedHistory.indexOf(true))
      expect(afterAuth.every((v) => v === true)).toBe(true)
    })
  })

  describe('Derived State from Machine', () => {
    it('should derive user from machine context', async () => {
      vi.mocked(mockApolloClient.query!).mockResolvedValue({
        data: {
          me: {
            id: 'user-123',
            email: 'test@example.com',
            displayName: 'Test User',
            firstName: 'Test',
            lastName: 'User',
            roles: ['customer', 'admin'],
            permissions: ['read:all'],
            emailVerified: true,
          },
        },
      })

      const store = createAuthMachineStore({
        apolloClient: mockApolloClient as ApolloClient<NormalizedCacheObject>,
        logger: mockLogger,
      })

      await vi.runAllTimersAsync()

      const { user } = store.getState()
      expect(user).not.toBeNull()
      expect(user?.id).toBe('user-123')
      expect(user?.email).toBe('test@example.com')
    })

    it('should derive error from machine context', async () => {
      vi.mocked(mockApolloClient.query!).mockResolvedValue({ data: { me: null } })

      const store = createAuthMachineStore({
        apolloClient: mockApolloClient as ApolloClient<NormalizedCacheObject>,
        logger: mockLogger,
      })

      await vi.runAllTimersAsync()

      // Mock failed login
      vi.mocked(mockApolloClient.mutate!).mockRejectedValue(new Error('Invalid credentials'))

      store.getState().login({
        email: 'test@example.com',
        cpf: '12345678900',
        password: 'wrong',
      })

      await vi.runAllTimersAsync()

      const { error } = store.getState()
      expect(error).not.toBeNull()
      expect(error?.message).toBeDefined()
    })

    it('should update machineState on transitions', async () => {
      // Use a slow query so we can observe the checkingAuth state
      vi.mocked(mockApolloClient.query!).mockImplementation(
        () =>
          new Promise((resolve) => {
            setTimeout(() => {
              resolve({ data: { me: null } })
            }, 1000)
          })
      )

      const store = createAuthMachineStore({
        apolloClient: mockApolloClient as ApolloClient<NormalizedCacheObject>,
        logger: mockLogger,
      })

      // Initially the store starts with hardcoded "initializing" before subscription fires
      // Then XState's subscription updates it to "checkingAuth" after actor.start()
      // The exact initial value depends on timing - the important thing is it transitions to idle
      const initialState = store.getState().machineState
      expect(['"initializing"', '"checkingAuth"']).toContain(initialState)

      await vi.runAllTimersAsync()

      // After checkAuth completes with no user
      expect(store.getState().machineState).toBe('"idle"')
    })
  })

  describe('Action Delegation to Machine', () => {
    it('should delegate login to machine', async () => {
      vi.mocked(mockApolloClient.query!).mockResolvedValue({ data: { me: null } })

      const store = createAuthMachineStore({
        apolloClient: mockApolloClient as ApolloClient<NormalizedCacheObject>,
        logger: mockLogger,
      })

      await vi.runAllTimersAsync()

      vi.mocked(mockApolloClient.mutate!).mockResolvedValue({
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

      store.getState().login({
        email: 'test@example.com',
        cpf: '12345678900',
        password: 'password123',
      })

      await vi.runAllTimersAsync()

      expect(store.getState().isAuthenticated).toBe(true)
    })

    it('should delegate logout to machine', async () => {
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

      const store = createAuthMachineStore({
        apolloClient: mockApolloClient as ApolloClient<NormalizedCacheObject>,
        logger: mockLogger,
      })

      await vi.runAllTimersAsync()
      expect(store.getState().isAuthenticated).toBe(true)

      vi.mocked(mockApolloClient.mutate!).mockResolvedValue({ data: { logout: true } })

      store.getState().logout()

      await vi.runAllTimersAsync()

      expect(store.getState().isAuthenticated).toBe(false)
      expect(store.getState().user).toBeNull()
    })

    it('should delegate forceLogout to machine', async () => {
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

      const store = createAuthMachineStore({
        apolloClient: mockApolloClient as ApolloClient<NormalizedCacheObject>,
        logger: mockLogger,
      })

      await vi.runAllTimersAsync()

      store.getState().forceLogout()

      // Force logout is immediate
      expect(store.getState().isAuthenticated).toBe(false)
    })

    it('should delegate clearError to machine', async () => {
      vi.mocked(mockApolloClient.query!).mockResolvedValue({ data: { me: null } })

      const store = createAuthMachineStore({
        apolloClient: mockApolloClient as ApolloClient<NormalizedCacheObject>,
        logger: mockLogger,
      })

      await vi.runAllTimersAsync()

      // Cause an error
      vi.mocked(mockApolloClient.mutate!).mockRejectedValue(new Error('Test error'))
      store.getState().login({
        email: 'test@example.com',
        cpf: '12345678900',
        password: 'wrong',
      })

      await vi.runAllTimersAsync()
      expect(store.getState().error).not.toBeNull()

      store.getState().clearError()

      await vi.runAllTimersAsync()
      expect(store.getState().error).toBeNull()
    })
  })

  describe('Callbacks', () => {
    it('should call onLogin callback when user logs in', async () => {
      const onLogin = vi.fn()

      vi.mocked(mockApolloClient.query!).mockResolvedValue({ data: { me: null } })

      const store = createAuthMachineStore({
        apolloClient: mockApolloClient as ApolloClient<NormalizedCacheObject>,
        logger: mockLogger,
        onLogin,
      })

      await vi.runAllTimersAsync()

      vi.mocked(mockApolloClient.mutate!).mockResolvedValue({
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

      store.getState().login({
        email: 'test@example.com',
        cpf: '12345678900',
        password: 'password123',
      })

      await vi.runAllTimersAsync()

      expect(onLogin).toHaveBeenCalledWith(
        expect.objectContaining({
          id: 'user-123',
          email: 'test@example.com',
        })
      )
    })

    it('should call onLogout callback when user logs out', async () => {
      const onLogout = vi.fn()

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

      const store = createAuthMachineStore({
        apolloClient: mockApolloClient as ApolloClient<NormalizedCacheObject>,
        logger: mockLogger,
        onLogout,
      })

      await vi.runAllTimersAsync()

      vi.mocked(mockApolloClient.mutate!).mockResolvedValue({ data: { logout: true } })

      store.getState().logout()

      await vi.runAllTimersAsync()

      expect(onLogout).toHaveBeenCalled()
    })

    it('should call onError callback on auth error', async () => {
      const onError = vi.fn()

      vi.mocked(mockApolloClient.query!).mockResolvedValue({ data: { me: null } })

      const store = createAuthMachineStore({
        apolloClient: mockApolloClient as ApolloClient<NormalizedCacheObject>,
        logger: mockLogger,
        onError,
      })

      await vi.runAllTimersAsync()

      vi.mocked(mockApolloClient.mutate!).mockRejectedValue(new Error('Auth failed'))

      store.getState().login({
        email: 'test@example.com',
        cpf: '12345678900',
        password: 'wrong',
      })

      await vi.runAllTimersAsync()

      expect(onError).toHaveBeenCalledWith(
        expect.objectContaining({
          message: expect.any(String),
        })
      )
    })
  })

  describe('Token Access', () => {
    it('should provide getAccessToken helper', async () => {
      vi.mocked(mockApolloClient.query!).mockResolvedValue({ data: { me: null } })

      const store = createAuthMachineStore({
        apolloClient: mockApolloClient as ApolloClient<NormalizedCacheObject>,
        logger: mockLogger,
      })

      await vi.runAllTimersAsync()

      // Initially no token
      expect(store.getState().getAccessToken()).toBeNull()

      // After login
      const accessToken = createMockJWT({
        sub: 'user-123',
        exp: futureTimestamp(3600),
        iat: Math.floor(Date.now() / 1000),
      })

      vi.mocked(mockApolloClient.mutate!).mockResolvedValue({
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
            accessToken,
            refreshToken: 'refresh-token',
            expiresIn: 3600,
            sessionId: 'session-123',
          },
        },
      })

      store.getState().login({
        email: 'test@example.com',
        cpf: '12345678900',
        password: 'password123',
      })

      await vi.runAllTimersAsync()

      expect(store.getState().getAccessToken()).toBe(accessToken)
    })
  })
})
