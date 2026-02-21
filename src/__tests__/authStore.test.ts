/**
 * Authentication Store Tests
 *
 * Comprehensive tests for createAuthStore factory function.
 * Tests critical auth fixes:
 * - Factory function pattern with dependency injection
 * - Empty refresh token handling
 * - Zanzibar-compliant roles array
 * - Token refresh scheduling
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { act } from '@testing-library/react'
import { createAuthStore, type AuthStoreConfig } from '../store/authStore'
import type { ApolloClient, NormalizedCacheObject } from '@apollo/client'

// Helper to create valid JWT token
function createMockJWT(payload: {
  sub: string
  exp: number
  iat: number
  roles?: string[]
  email?: string
}): string {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
  const payloadStr = btoa(JSON.stringify(payload))
  const signature = btoa('mock-signature')
  return `${header}.${payloadStr}.${signature}`
}

// Helper to create future timestamp (seconds from now)
function futureTimestamp(seconds: number): number {
  return Math.floor(Date.now() / 1000) + seconds
}

// Helper to create past timestamp (seconds ago)
function pastTimestamp(seconds: number): number {
  return Math.floor(Date.now() / 1000) - seconds
}

describe('createAuthStore', () => {
  let mockApolloClient: Partial<ApolloClient<NormalizedCacheObject>>
  let mockLogger: AuthStoreConfig['logger']
  let store: ReturnType<typeof createAuthStore>

  beforeEach(() => {
    vi.useFakeTimers()

    // Mock Apollo client
    mockApolloClient = {
      mutate: vi.fn(),
      query: vi.fn(),
      clearStore: vi.fn().mockResolvedValue(undefined),
    }

    // Mock logger
    mockLogger = {
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
      debug: vi.fn(),
    }

    // Create fresh store for each test
    store = createAuthStore({
      apolloClient: mockApolloClient as ApolloClient<NormalizedCacheObject>,
      logger: mockLogger,
      storageName: 'test-auth-storage',
    })
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.clearAllMocks()
    localStorage.clear()
  })

  describe('Factory Function Pattern', () => {
    it('should create store with dependency injection', () => {
      expect(store).toBeDefined()
      expect(store.getState).toBeDefined()
      expect(store.setState).toBeDefined()
    })

    it('should use injected Apollo client for mutations', async () => {
      const mockLoginResponse = {
        data: {
          login: {
            user: {
              id: 'user-123',
              email: 'test@example.com',
              displayName: 'Test User',
              roles: ['customer'],
              permissions: ['read:products'],
              emailVerified: true,
            },
            accessToken: createMockJWT({
              sub: 'user-123',
              exp: futureTimestamp(3600),
              iat: pastTimestamp(0),
            }),
            refreshToken: 'refresh-token-123',
            expiresIn: 3600,
            sessionId: 'session-123',
          },
        },
      }

      vi.mocked(mockApolloClient.mutate!).mockResolvedValue(mockLoginResponse)

      await act(async () => {
        await store.getState().login({
          email: 'test@example.com',
          cpf: '12345678900',
          password: 'password123',
        })
      })

      expect(mockApolloClient.mutate).toHaveBeenCalled()
      expect(store.getState().isAuthenticated).toBe(true)
    })

    it('should use injected logger', async () => {
      const mockLoginResponse = {
        data: {
          login: {
            user: {
              id: 'user-123',
              email: 'test@example.com',
              roles: ['customer'],
              permissions: [],
              emailVerified: true,
            },
            accessToken: createMockJWT({
              sub: 'user-123',
              exp: futureTimestamp(3600),
              iat: pastTimestamp(0),
            }),
            refreshToken: 'refresh-token-123',
            expiresIn: 3600,
            sessionId: 'session-123',
          },
        },
      }

      vi.mocked(mockApolloClient.mutate!).mockResolvedValue(mockLoginResponse)

      await act(async () => {
        await store.getState().login({
          email: 'test@example.com',
          cpf: '12345678900',
          password: 'password123',
        })
      })

      expect(mockLogger?.info).toHaveBeenCalledWith(
        'Login request',
        expect.objectContaining({ email: 'test@example.com' }),
        'Auth'
      )
    })

    it('should allow custom storage name', () => {
      const customStore = createAuthStore({
        apolloClient: mockApolloClient as ApolloClient<NormalizedCacheObject>,
        storageName: 'custom-auth-storage',
      })

      expect(customStore).toBeDefined()
    })

    it('should use default logger when not provided', () => {
      const storeWithDefaultLogger = createAuthStore({
        apolloClient: mockApolloClient as ApolloClient<NormalizedCacheObject>,
      })

      expect(storeWithDefaultLogger).toBeDefined()
    })
  })

  describe('Empty Refresh Token Handling (Cookie-Based Auth)', () => {
    /**
     * CRITICAL FIX: When AUTH_COOKIES_ENABLED=true on backend, the refresh token
     * is stored in an HttpOnly cookie, NOT in the response body. The frontend
     * should still schedule refresh and attempt refresh operations even when
     * the stored refresh token is empty - the backend will read from the cookie.
     */

    it('should schedule refresh even when stored refresh token is empty (cookie-based auth)', async () => {
      const mockLoginResponse = {
        data: {
          login: {
            user: {
              id: 'user-123',
              email: 'test@example.com',
              roles: ['customer'],
              permissions: [],
              emailVerified: true,
            },
            accessToken: createMockJWT({
              sub: 'user-123',
              exp: futureTimestamp(3600),
              iat: pastTimestamp(0),
            }),
            refreshToken: '', // Empty refresh token - backend stores in HttpOnly cookie
            expiresIn: 3600,
            sessionId: 'session-123',
          },
        },
      }

      vi.mocked(mockApolloClient.mutate!).mockResolvedValue(mockLoginResponse)

      await act(async () => {
        await store.getState().login({
          email: 'test@example.com',
          cpf: '12345678900',
          password: 'password123',
        })
      })

      // Advance timers to allow scheduleTokenRefresh to be called
      await vi.advanceTimersByTimeAsync(100)

      // Should schedule refresh with timing info (uses in-memory token)
      expect(mockLogger?.info).toHaveBeenCalledWith(
        'Scheduling token refresh',
        expect.objectContaining({
          expiresIn: expect.any(Number),
          refreshIn: expect.any(Number),
        }),
        'Auth'
      )
    })

    it('should schedule refresh even when refresh token is whitespace (cookie-based auth)', async () => {
      const accessToken = createMockJWT({
        sub: 'user-123',
        exp: futureTimestamp(3600),
        iat: pastTimestamp(0),
      })

      // Set up store with whitespace refresh token - need to use setTokens to set in-memory token
      await act(async () => {
        store.getState().setTokens({
          accessToken,
          refreshToken: '   ', // Whitespace only - backend uses HttpOnly cookie
          expiresIn: 3600,
          tokenType: 'Bearer' as const,
        })
        store.setState({ isAuthenticated: true })
      })

      await act(async () => {
        store.getState().scheduleTokenRefresh()
      })

      // Should schedule refresh (in-memory token is set via setTokens)
      expect(mockLogger?.info).toHaveBeenCalledWith(
        'Scheduling token refresh',
        expect.objectContaining({
          expiresIn: expect.any(Number),
          refreshIn: expect.any(Number),
        }),
        'Auth'
      )
    })

    it('should schedule refresh with valid access token but empty refresh token', async () => {
      const validToken = createMockJWT({
        sub: 'user-123',
        exp: futureTimestamp(900), // 15 minutes - refresh should trigger at ~14 min
        iat: pastTimestamp(0),
      })

      // Set up store with valid access token but empty refresh token
      await act(async () => {
        store.getState().setTokens({
          accessToken: validToken,
          refreshToken: '',
          expiresIn: 900,
          tokenType: 'Bearer' as const,
        })
        store.setState({ isAuthenticated: true })
      })

      await act(async () => {
        store.getState().scheduleTokenRefresh()
      })

      // Should schedule refresh (in-memory token is set)
      expect(mockLogger?.info).toHaveBeenCalledWith(
        'Scheduling token refresh',
        expect.objectContaining({
          expiresIn: expect.any(Number),
          refreshIn: expect.any(Number),
        }),
        'Auth'
      )
    })

    it('should attempt refresh even with empty stored token (backend reads from cookie)', async () => {
      // Mock successful refresh response (backend read from HttpOnly cookie)
      const mockRefreshResponse = {
        data: {
          refreshToken: {
            accessToken: createMockJWT({
              sub: 'user-123',
              exp: futureTimestamp(3600),
              iat: pastTimestamp(0),
            }),
            expiresIn: 3600,
          },
        },
      }

      vi.mocked(mockApolloClient.mutate!).mockResolvedValue(mockRefreshResponse)

      await act(async () => {
        store.setState({
          tokens: {
            accessToken: createMockJWT({
              sub: 'user-123',
              exp: futureTimestamp(300), // About to expire
              iat: pastTimestamp(0),
            }),
            refreshToken: '', // Empty - backend uses HttpOnly cookie
            expiresIn: 300,
            tokenType: 'Bearer' as const,
          },
          isAuthenticated: true,
        })
      })

      // Should NOT throw - attempt refresh with null token (backend reads from cookie)
      await act(async () => {
        await store.getState().refreshToken()
      })

      // Verify the mutation was called with null refreshToken (backend reads from cookie)
      expect(mockApolloClient.mutate).toHaveBeenCalledWith(
        expect.objectContaining({
          variables: { refreshToken: null },
        })
      )
    })

    it('should attempt refresh even with no tokens (backend uses HttpOnly cookie)', async () => {
      // Use setTokens(null) to clear both Zustand state AND module-level currentAccessToken
      await act(async () => {
        store.getState().setTokens(null)
        store.setState({ isAuthenticated: false })
      })

      // Mock failed refresh (no valid session)
      mockApolloClient.mutate.mockRejectedValueOnce(new Error('Token refresh failed'))

      // When tokens are null, we still attempt refresh because backend may use HttpOnly cookie
      // This enables session restoration after page refresh when in-memory tokens are lost
      await expect(
        act(async () => {
          await store.getState().refreshToken()
        })
      ).rejects.toThrow('Token refresh failed')
    })
  })

  describe('Zanzibar-Compliant Roles Array', () => {
    it('should handle roles as array from login response', async () => {
      const mockLoginResponse = {
        data: {
          login: {
            user: {
              id: 'user-123',
              email: 'test@example.com',
              displayName: 'Test User',
              roles: ['customer', 'admin'], // Array of roles
              permissions: ['read:all', 'write:all'],
              emailVerified: true,
            },
            accessToken: createMockJWT({
              sub: 'user-123',
              exp: futureTimestamp(3600),
              iat: pastTimestamp(0),
              roles: ['customer', 'admin'],
            }),
            refreshToken: 'refresh-token-123',
            expiresIn: 3600,
            sessionId: 'session-123',
          },
        },
      }

      vi.mocked(mockApolloClient.mutate!).mockResolvedValue(mockLoginResponse)

      await act(async () => {
        await store.getState().login({
          email: 'test@example.com',
          cpf: '12345678900',
          password: 'password123',
        })
      })

      const { user } = store.getState()
      expect(user?.roles).toEqual(['customer', 'admin'])
      expect(Array.isArray(user?.roles)).toBe(true)
    })

    it('should handle permissions array from login response', async () => {
      const mockLoginResponse = {
        data: {
          login: {
            user: {
              id: 'user-123',
              email: 'test@example.com',
              displayName: 'Test User',
              roles: ['admin'],
              permissions: ['products:read', 'products:write', 'users:manage'],
              emailVerified: true,
            },
            accessToken: createMockJWT({
              sub: 'user-123',
              exp: futureTimestamp(3600),
              iat: pastTimestamp(0),
            }),
            refreshToken: 'refresh-token-123',
            expiresIn: 3600,
            sessionId: 'session-123',
          },
        },
      }

      vi.mocked(mockApolloClient.mutate!).mockResolvedValue(mockLoginResponse)

      await act(async () => {
        await store.getState().login({
          email: 'test@example.com',
          cpf: '12345678900',
          password: 'password123',
        })
      })

      const { user } = store.getState()
      expect(user?.permissions).toEqual(['products:read', 'products:write', 'users:manage'])
    })

    it('should fallback to legacy single role when roles array missing', async () => {
      const mockLoginResponse = {
        data: {
          login: {
            user: {
              id: 'user-123',
              email: 'test@example.com',
              displayName: 'Test User',
              role: 'admin', // Legacy single role
              // No roles array
              permissions: [],
              emailVerified: true,
            },
            accessToken: createMockJWT({
              sub: 'user-123',
              exp: futureTimestamp(3600),
              iat: pastTimestamp(0),
            }),
            refreshToken: 'refresh-token-123',
            expiresIn: 3600,
            sessionId: 'session-123',
          },
        },
      }

      vi.mocked(mockApolloClient.mutate!).mockResolvedValue(mockLoginResponse)

      await act(async () => {
        await store.getState().login({
          email: 'test@example.com',
          cpf: '12345678900',
          password: 'password123',
        })
      })

      const { user } = store.getState()
      expect(user?.roles).toEqual(['admin'])
      expect(Array.isArray(user?.roles)).toBe(true)
    })

    it('should default to customer role when neither roles array nor role field', async () => {
      const mockLoginResponse = {
        data: {
          login: {
            user: {
              id: 'user-123',
              email: 'test@example.com',
              displayName: 'Test User',
              // No roles or role field
              permissions: [],
              emailVerified: true,
            },
            accessToken: createMockJWT({
              sub: 'user-123',
              exp: futureTimestamp(3600),
              iat: pastTimestamp(0),
            }),
            refreshToken: 'refresh-token-123',
            expiresIn: 3600,
            sessionId: 'session-123',
          },
        },
      }

      vi.mocked(mockApolloClient.mutate!).mockResolvedValue(mockLoginResponse)

      await act(async () => {
        await store.getState().login({
          email: 'test@example.com',
          cpf: '12345678900',
          password: 'password123',
        })
      })

      const { user } = store.getState()
      expect(user?.roles).toEqual(['customer'])
    })

    it('should handle roles array in checkAuth response', async () => {
      const mockMeResponse = {
        data: {
          me: {
            id: 'user-123',
            email: 'test@example.com',
            displayName: 'Test User',
            roles: ['supplier', 'customer'],
            permissions: ['inventory:manage'],
            emailVerified: true,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
          },
        },
      }

      vi.mocked(mockApolloClient.query!).mockResolvedValue(mockMeResponse)

      await act(async () => {
        await store.getState().checkAuth()
      })

      const { user } = store.getState()
      expect(user?.roles).toEqual(['supplier', 'customer'])
    })
  })

  describe('Token Refresh Scheduling', () => {
    it('should schedule refresh before token expiry', async () => {
      const expiresIn = 3600 // 1 hour
      const validToken = createMockJWT({
        sub: 'user-123',
        exp: futureTimestamp(expiresIn),
        iat: pastTimestamp(0),
      })

      await act(async () => {
        store.setState({
          tokens: {
            accessToken: validToken,
            refreshToken: 'valid-refresh-token',
            expiresIn,
            tokenType: 'Bearer' as const,
          },
          isAuthenticated: true,
        })
      })

      await act(async () => {
        store.getState().scheduleTokenRefresh()
      })

      expect(mockLogger?.info).toHaveBeenCalledWith(
        'Scheduling token refresh',
        expect.objectContaining({
          expiresIn: expect.any(Number),
          refreshIn: expect.any(Number),
        }),
        'Auth'
      )
    })

    it('should cancel existing refresh timer when scheduling new one', async () => {
      const validToken = createMockJWT({
        sub: 'user-123',
        exp: futureTimestamp(3600),
        iat: pastTimestamp(0),
      })

      await act(async () => {
        store.setState({
          tokens: {
            accessToken: validToken,
            refreshToken: 'valid-refresh-token',
            expiresIn: 3600,
            tokenType: 'Bearer' as const,
          },
          isAuthenticated: true,
        })
      })

      // Schedule first refresh
      await act(async () => {
        store.getState().scheduleTokenRefresh()
      })

      const firstTimerId = store.getState().refreshTimerId

      // Schedule second refresh (should cancel first)
      await act(async () => {
        store.getState().scheduleTokenRefresh()
      })

      const secondTimerId = store.getState().refreshTimerId

      expect(secondTimerId).not.toBe(firstTimerId)
    })

    it('should cancel refresh timer on logout', async () => {
      const validToken = createMockJWT({
        sub: 'user-123',
        exp: futureTimestamp(3600),
        iat: pastTimestamp(0),
      })

      await act(async () => {
        store.setState({
          tokens: {
            accessToken: validToken,
            refreshToken: 'valid-refresh-token',
            expiresIn: 3600,
            tokenType: 'Bearer' as const,
            sessionId: 'session-123',
          },
          isAuthenticated: true,
        })
      })

      await act(async () => {
        store.getState().scheduleTokenRefresh()
      })

      expect(store.getState().refreshTimerId).not.toBeNull()

      await act(async () => {
        await store.getState().logout()
      })

      // After logout, state should be cleared
      expect(store.getState().isAuthenticated).toBe(false)
      expect(store.getState().tokens).toBeNull()
    })

    it('should cancel refresh timer on forceLogout', async () => {
      const validToken = createMockJWT({
        sub: 'user-123',
        exp: futureTimestamp(3600),
        iat: pastTimestamp(0),
      })

      await act(async () => {
        store.setState({
          tokens: {
            accessToken: validToken,
            refreshToken: 'valid-refresh-token',
            expiresIn: 3600,
            tokenType: 'Bearer' as const,
          },
          isAuthenticated: true,
        })
      })

      await act(async () => {
        store.getState().scheduleTokenRefresh()
      })

      await act(async () => {
        store.getState().forceLogout()
      })

      expect(store.getState().isAuthenticated).toBe(false)
      expect(store.getState().tokens).toBeNull()
      expect(mockLogger?.info).toHaveBeenCalledWith(
        'Force logout complete',
        {},
        'Auth'
      )
    })

    it('should skip scheduling when no access token', async () => {
      await act(async () => {
        store.setState({
          tokens: null,
          isAuthenticated: false,
        })
      })

      await act(async () => {
        store.getState().scheduleTokenRefresh()
      })

      expect(mockLogger?.debug).toHaveBeenCalledWith(
        'No access token - skipping refresh scheduling',
        {},
        'Auth'
      )
    })
  })

  describe('Login/Logout Flow', () => {
    it('should update state correctly on successful login', async () => {
      const mockLoginResponse = {
        data: {
          login: {
            user: {
              id: 'user-123',
              email: 'test@example.com',
              displayName: 'Test User',
              firstName: 'Test',
              lastName: 'User',
              roles: ['customer'],
              permissions: [],
              emailVerified: true,
            },
            accessToken: createMockJWT({
              sub: 'user-123',
              exp: futureTimestamp(3600),
              iat: pastTimestamp(0),
            }),
            refreshToken: 'refresh-token-123',
            expiresIn: 3600,
            sessionId: 'session-123',
          },
        },
      }

      vi.mocked(mockApolloClient.mutate!).mockResolvedValue(mockLoginResponse)

      expect(store.getState().isAuthenticated).toBe(false)

      await act(async () => {
        await store.getState().login({
          email: 'test@example.com',
          cpf: '12345678900',
          password: 'password123',
        })
      })

      const state = store.getState()
      expect(state.isAuthenticated).toBe(true)
      expect(state.user?.email).toBe('test@example.com')
      expect(state.tokens?.sessionId).toBe('session-123')
      expect(state.error).toBeNull()
      expect(state.isLoading).toBe(false)
    })

    it('should clear state on logout', async () => {
      // Set up authenticated state
      await act(async () => {
        store.setState({
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
              exp: futureTimestamp(3600),
              iat: pastTimestamp(0),
            }),
            refreshToken: 'refresh-token',
            expiresIn: 3600,
            tokenType: 'Bearer' as const,
            sessionId: 'session-123',
          },
          isAuthenticated: true,
        })
      })

      await act(async () => {
        await store.getState().logout()
      })

      const state = store.getState()
      expect(state.isAuthenticated).toBe(false)
      expect(state.user).toBeNull()
      expect(state.tokens).toBeNull()
    })

    it('should handle login error gracefully', async () => {
      const mockError = new Error('Invalid credentials')
      vi.mocked(mockApolloClient.mutate!).mockRejectedValue(mockError)

      await expect(
        act(async () => {
          await store.getState().login({
            email: 'test@example.com',
            cpf: '12345678900',
            password: 'wrong-password',
          })
        })
      ).rejects.toThrow()

      const state = store.getState()
      expect(state.isAuthenticated).toBe(false)
      expect(state.user).toBeNull()
      expect(state.error).not.toBeNull()
      expect(state.isLoading).toBe(false)
    })
  })

  describe('Error Handling', () => {
    it('should clear error on clearError', async () => {
      await act(async () => {
        store.setState({
          error: {
            message: 'Test error',
            code: 'UNKNOWN_ERROR',
            severity: 'medium',
            isOperational: true,
            name: 'AppError',
            getUserMessage: () => 'Test error',
            shouldReport: () => false,
            toJSON: () => ({
              name: 'AppError',
              message: 'Test error',
              code: 'UNKNOWN_ERROR',
              severity: 'medium',
            }),
          } as any,
        })
      })

      expect(store.getState().error).not.toBeNull()

      await act(async () => {
        store.getState().clearError()
      })

      expect(store.getState().error).toBeNull()
    })
  })
})
