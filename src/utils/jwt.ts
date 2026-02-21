/**
 * JWT Token Utilities
 *
 * Secure client-side JWT parsing and validation
 * Follows RFC 7519 JWT standard
 *
 * SECURITY NOTE: This only validates expiry on the client side.
 * The backend MUST always validate tokens server-side.
 */

import { logger } from './logger'

/**
 * JWT Payload interface based on RFC 7519
 */
export interface JWTPayload {
  /** Subject (user ID) */
  sub: string
  /** Expiration time (Unix timestamp in seconds) */
  exp: number
  /** Issued at (Unix timestamp in seconds) */
  iat: number
  /** Issuer */
  iss?: string
  /** Audience */
  aud?: string
  /** JWT ID */
  jti?: string
  /** Roles array */
  roles?: string[]
  /** Email address */
  email?: string
}

/**
 * Safely parse a JWT token without verification
 *
 * WARNING: This does NOT verify the signature. Only use for reading claims.
 * Always verify tokens server-side.
 *
 * @param token - JWT token string
 * @returns Parsed payload or null if invalid
 */
export function parseJWT(token: string): JWTPayload | null {
  try {
    // JWT format: header.payload.signature
    const parts = token.split('.')
    if (parts.length !== 3) {
      logger.warn('Invalid JWT format - expected 3 parts', { parts: parts.length }, 'JWT')
      return null
    }

    // Decode base64url payload (second part)
    const payload = parts[1]

    // Base64url decode (replace URL-safe chars and add padding)
    const base64 = payload.replace(/-/g, '+').replace(/_/g, '/')
    const paddedBase64 = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=')

    const jsonPayload = atob(paddedBase64)
    const parsed = JSON.parse(jsonPayload)

    // Validate required claims
    if (!parsed.sub || !parsed.exp || !parsed.iat) {
      logger.warn(
        'JWT missing required claims',
        {
          hasSub: !!parsed.sub,
          hasExp: !!parsed.exp,
          hasIat: !!parsed.iat,
        },
        'JWT'
      )
      return null
    }

    return parsed as JWTPayload
  } catch (error) {
    logger.error('Failed to parse JWT', { error }, 'JWT')
    return null
  }
}

/**
 * Check if a JWT token is expired
 *
 * Uses the standard `exp` claim with optional buffer for clock skew
 *
 * @param token - JWT token string
 * @param bufferSeconds - Grace period in seconds (default: 60s for clock skew)
 * @returns true if expired, false if valid
 */
export function isTokenExpired(token: string, bufferSeconds = 60): boolean {
  const payload = parseJWT(token)
  if (!payload?.exp) {
    logger.warn('Cannot check expiry - invalid token or missing exp claim', {}, 'JWT')
    return true // Treat invalid tokens as expired
  }

  const now = Math.floor(Date.now() / 1000) // Current Unix timestamp
  const expiresAt = payload.exp - bufferSeconds // Account for clock skew

  const isExpired = now >= expiresAt

  if (isExpired) {
    logger.info(
      'Token expired',
      {
        now,
        exp: payload.exp,
        expiredSecondsAgo: now - payload.exp,
      },
      'JWT'
    )
  }

  return isExpired
}

/**
 * Get the expiration time of a JWT token
 *
 * @param token - JWT token string
 * @returns Date object of expiry or null if invalid
 */
export function getTokenExpiry(token: string): Date | null {
  const payload = parseJWT(token)
  if (!payload?.exp) return null

  return new Date(payload.exp * 1000) // Convert Unix timestamp to milliseconds
}

/**
 * Alias for getTokenExpiry for backwards compatibility
 * @deprecated Use getTokenExpiry instead
 */
export const getTokenExpiryTime: (token: string) => Date | null = getTokenExpiry

/**
 * Get the issued-at time of a JWT token
 *
 * @param token - JWT token string
 * @returns Date object of issue time or null if invalid
 */
export function getTokenIssuedAt(token: string): Date | null {
  const payload = parseJWT(token)
  if (!payload?.iat) return null

  return new Date(payload.iat * 1000)
}

/**
 * Calculate how many seconds until token expires
 *
 * @param token - JWT token string
 * @returns Seconds until expiry (negative if already expired) or null if invalid
 */
export function getSecondsUntilExpiry(token: string): number | null {
  const payload = parseJWT(token)
  if (!payload?.exp) return null

  const now = Math.floor(Date.now() / 1000)
  return payload.exp - now
}

/**
 * Check if token needs refresh (expires within threshold)
 *
 * Best practice: Refresh tokens before they expire to avoid auth failures
 *
 * @param token - JWT token string
 * @param thresholdSeconds - Refresh threshold in seconds (default: 5 minutes)
 * @returns true if should refresh
 */
export function shouldRefreshToken(token: string, thresholdSeconds = 300): boolean {
  const secondsUntilExpiry = getSecondsUntilExpiry(token)
  if (secondsUntilExpiry === null) return true // Refresh invalid tokens

  return secondsUntilExpiry <= thresholdSeconds
}

/**
 * Extract user information from JWT payload
 *
 * @param token - JWT token string
 * @returns User info object or null if invalid
 */
export function getUserFromToken(token: string): {
  userId: string
  roles?: string[]
  email?: string
} | null {
  const payload = parseJWT(token)
  if (!payload) return null

  return {
    userId: payload.sub,
    roles: payload.roles,
    email: payload.email,
  }
}

/**
 * Validate token structure and basic claims
 *
 * This does NOT verify the signature - always verify server-side
 *
 * @param token - JWT token string
 * @returns Validation result with errors if invalid
 */
export function validateTokenStructure(token: string): {
  valid: boolean
  errors: string[]
} {
  const errors: string[] = []

  if (!token || typeof token !== 'string') {
    errors.push('Token is not a string')
    return { valid: false, errors }
  }

  const parts = token.split('.')
  if (parts.length !== 3) {
    errors.push(`Invalid JWT structure - expected 3 parts, got ${parts.length}`)
    return { valid: false, errors }
  }

  const payload = parseJWT(token)
  if (!payload) {
    errors.push('Failed to parse JWT payload')
    return { valid: false, errors }
  }

  // Validate required claims
  if (!payload.sub) errors.push('Missing required claim: sub')
  if (!payload.exp) errors.push('Missing required claim: exp')
  if (!payload.iat) errors.push('Missing required claim: iat')

  // Validate expiry is in future
  if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
    errors.push('Token is expired')
  }

  // Validate iat is in past
  if (payload.iat && payload.iat > Math.floor(Date.now() / 1000)) {
    errors.push('Token issued in the future')
  }

  return {
    valid: errors.length === 0,
    errors,
  }
}
