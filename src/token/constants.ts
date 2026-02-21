/**
 * Token Manager Constants
 *
 * Centralized constants for token management
 */

/**
 * localStorage key for storing the access token
 * Used by Apollo Client for authentication headers
 */
export const AUTH_TOKEN_KEY = 'auth_access_token'

/**
 * localStorage key for Zustand persist storage
 * Contains full auth state including tokens and user
 */
export const ZUSTAND_STORAGE_KEY = 'auth-storage'
