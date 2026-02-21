/**
 * JWT Utility Tests
 *
 * Tests for JWT parsing, validation, and expiry checking.
 * Critical for token management and session validation.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  parseJWT,
  isTokenExpired,
  getTokenExpiry,
  getSecondsUntilExpiry,
  shouldRefreshToken,
  getUserFromToken,
  validateTokenStructure,
} from '../utils/jwt'

// Helper to create valid JWT token
function createMockJWT(payload: Record<string, unknown>): string {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
  const payloadStr = btoa(JSON.stringify(payload))
  const signature = btoa('mock-signature')
  return `${header}.${payloadStr}.${signature}`
}

// Helper to create timestamp in seconds
function futureTimestamp(seconds: number): number {
  return Math.floor(Date.now() / 1000) + seconds
}

function pastTimestamp(seconds: number): number {
  return Math.floor(Date.now() / 1000) - seconds
}

describe('JWT Utilities', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  describe('parseJWT', () => {
    it('should parse valid JWT token', () => {
      const token = createMockJWT({
        sub: 'user-123',
        exp: futureTimestamp(3600),
        iat: pastTimestamp(0),
        email: 'test@example.com',
        roles: ['admin'],
      })

      const payload = parseJWT(token)

      expect(payload).not.toBeNull()
      expect(payload?.sub).toBe('user-123')
      expect(payload?.email).toBe('test@example.com')
      expect(payload?.roles).toEqual(['admin'])
    })

    it('should return null for invalid JWT format (wrong number of parts)', () => {
      const invalidToken = 'invalid.token'
      const payload = parseJWT(invalidToken)
      expect(payload).toBeNull()
    })

    it('should return null for invalid base64 payload', () => {
      const invalidToken = 'header.!!!invalid!!!.signature'
      const payload = parseJWT(invalidToken)
      expect(payload).toBeNull()
    })

    it('should return null when missing required claims', () => {
      const token = createMockJWT({
        // Missing sub, exp, iat
        email: 'test@example.com',
      })

      const payload = parseJWT(token)
      expect(payload).toBeNull()
    })

    it('should handle base64url encoding (URL-safe characters)', () => {
      // Create token with values that would use URL-safe characters
      const token = createMockJWT({
        sub: 'user-with-special-chars_+/=',
        exp: futureTimestamp(3600),
        iat: pastTimestamp(0),
      })

      const payload = parseJWT(token)
      expect(payload).not.toBeNull()
      expect(payload?.sub).toBe('user-with-special-chars_+/=')
    })
  })

  describe('isTokenExpired', () => {
    it('should return false for valid non-expired token', () => {
      const token = createMockJWT({
        sub: 'user-123',
        exp: futureTimestamp(3600), // 1 hour from now
        iat: pastTimestamp(0),
      })

      expect(isTokenExpired(token)).toBe(false)
    })

    it('should return true for expired token', () => {
      const token = createMockJWT({
        sub: 'user-123',
        exp: pastTimestamp(3600), // 1 hour ago
        iat: pastTimestamp(7200),
      })

      expect(isTokenExpired(token)).toBe(true)
    })

    it('should respect buffer time for clock skew', () => {
      const token = createMockJWT({
        sub: 'user-123',
        exp: futureTimestamp(30), // Expires in 30 seconds
        iat: pastTimestamp(0),
      })

      // With default 60s buffer, token should be considered expired
      expect(isTokenExpired(token)).toBe(true)

      // With 0s buffer, token should be valid
      expect(isTokenExpired(token, 0)).toBe(false)
    })

    it('should return true for invalid token', () => {
      expect(isTokenExpired('invalid-token')).toBe(true)
    })
  })

  describe('getTokenExpiry', () => {
    it('should return Date object for valid token', () => {
      const expTime = futureTimestamp(3600)
      const token = createMockJWT({
        sub: 'user-123',
        exp: expTime,
        iat: pastTimestamp(0),
      })

      const expiry = getTokenExpiry(token)

      expect(expiry).toBeInstanceOf(Date)
      expect(expiry?.getTime()).toBe(expTime * 1000)
    })

    it('should return null for invalid token', () => {
      expect(getTokenExpiry('invalid-token')).toBeNull()
    })
  })

  describe('getSecondsUntilExpiry', () => {
    it('should return positive seconds for valid non-expired token', () => {
      const token = createMockJWT({
        sub: 'user-123',
        exp: futureTimestamp(3600),
        iat: pastTimestamp(0),
      })

      const seconds = getSecondsUntilExpiry(token)

      expect(seconds).not.toBeNull()
      expect(seconds).toBeGreaterThan(3500) // Allow some margin
      expect(seconds).toBeLessThanOrEqual(3600)
    })

    it('should return negative seconds for expired token', () => {
      const token = createMockJWT({
        sub: 'user-123',
        exp: pastTimestamp(3600), // Expired 1 hour ago
        iat: pastTimestamp(7200),
      })

      const seconds = getSecondsUntilExpiry(token)

      expect(seconds).not.toBeNull()
      expect(seconds).toBeLessThan(0)
    })

    it('should return null for invalid token', () => {
      expect(getSecondsUntilExpiry('invalid-token')).toBeNull()
    })
  })

  describe('shouldRefreshToken', () => {
    it('should return false when token has plenty of time left', () => {
      const token = createMockJWT({
        sub: 'user-123',
        exp: futureTimestamp(3600), // 1 hour left
        iat: pastTimestamp(0),
      })

      expect(shouldRefreshToken(token)).toBe(false) // Default threshold is 300s
    })

    it('should return true when token is within refresh threshold', () => {
      const token = createMockJWT({
        sub: 'user-123',
        exp: futureTimestamp(200), // 200 seconds left
        iat: pastTimestamp(0),
      })

      expect(shouldRefreshToken(token)).toBe(true) // Default threshold is 300s
    })

    it('should respect custom threshold', () => {
      const token = createMockJWT({
        sub: 'user-123',
        exp: futureTimestamp(500), // 500 seconds left
        iat: pastTimestamp(0),
      })

      expect(shouldRefreshToken(token, 300)).toBe(false) // 500 > 300
      expect(shouldRefreshToken(token, 600)).toBe(true) // 500 < 600
    })

    it('should return true for invalid token', () => {
      expect(shouldRefreshToken('invalid-token')).toBe(true)
    })
  })

  describe('getUserFromToken', () => {
    it('should extract user info from token', () => {
      const token = createMockJWT({
        sub: 'user-123',
        exp: futureTimestamp(3600),
        iat: pastTimestamp(0),
        email: 'test@example.com',
        roles: ['admin', 'user'],
      })

      const userInfo = getUserFromToken(token)

      expect(userInfo).not.toBeNull()
      expect(userInfo?.userId).toBe('user-123')
      expect(userInfo?.email).toBe('test@example.com')
      expect(userInfo?.roles).toEqual(['admin', 'user'])
    })

    it('should handle token without optional fields', () => {
      const token = createMockJWT({
        sub: 'user-123',
        exp: futureTimestamp(3600),
        iat: pastTimestamp(0),
      })

      const userInfo = getUserFromToken(token)

      expect(userInfo).not.toBeNull()
      expect(userInfo?.userId).toBe('user-123')
      expect(userInfo?.email).toBeUndefined()
      expect(userInfo?.roles).toBeUndefined()
    })

    it('should return null for invalid token', () => {
      expect(getUserFromToken('invalid-token')).toBeNull()
    })
  })

  describe('validateTokenStructure', () => {
    it('should return valid for well-formed token', () => {
      const token = createMockJWT({
        sub: 'user-123',
        exp: futureTimestamp(3600),
        iat: pastTimestamp(0),
      })

      const result = validateTokenStructure(token)

      expect(result.valid).toBe(true)
      expect(result.errors).toHaveLength(0)
    })

    it('should detect missing required claims', () => {
      const tokenMissingSub = createMockJWT({
        // Missing sub
        exp: futureTimestamp(3600),
        iat: pastTimestamp(0),
      })

      // parseJWT returns null for missing required claims
      const result = validateTokenStructure(tokenMissingSub)
      expect(result.valid).toBe(false)
    })

    it('should detect invalid JWT structure', () => {
      const result = validateTokenStructure('not-a-jwt')

      expect(result.valid).toBe(false)
      expect(result.errors).toContain('Invalid JWT structure - expected 3 parts, got 1')
    })

    it('should detect expired token', () => {
      const token = createMockJWT({
        sub: 'user-123',
        exp: pastTimestamp(3600), // Expired
        iat: pastTimestamp(7200),
      })

      const result = validateTokenStructure(token)

      expect(result.valid).toBe(false)
      expect(result.errors).toContain('Token is expired')
    })

    it('should detect token issued in future', () => {
      const token = createMockJWT({
        sub: 'user-123',
        exp: futureTimestamp(7200),
        iat: futureTimestamp(3600), // Future issued time
      })

      const result = validateTokenStructure(token)

      expect(result.valid).toBe(false)
      expect(result.errors).toContain('Token issued in the future')
    })

    it('should handle null/undefined token', () => {
      const result = validateTokenStructure(null as unknown as string)

      expect(result.valid).toBe(false)
      expect(result.errors).toContain('Token is not a string')
    })
  })
})
