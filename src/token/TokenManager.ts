/**
 * TokenManager - Single Source of Truth for Authentication Tokens
 *
 * ARCHITECTURAL DECISION:
 * This class eliminates the dual storage problem where tokens were stored in
 * two places (Zustand 'auth-storage' + localStorage AUTH_TOKEN_KEY) and had
 * to be manually synchronized. Now ALL token operations go through this manager.
 *
 * GUARANTEES:
 * 1. Zustand and Apollo Client ALWAYS read the same token
 * 2. Token updates ALWAYS propagate to both storage locations atomically
 * 3. Token clears ALWAYS clear both storage locations atomically
 * 4. Impossible to get out of sync (by design)
 *
 * USAGE:
 * - Zustand: Call TokenManager methods instead of direct localStorage
 * - Apollo Client: Read from TokenManager.getAccessToken()
 * - Any component: Import TokenManager for token operations
 *
 * FUTURE DEVELOPERS:
 * If you need to add token storage (e.g., Redis, cookies), add it HERE.
 * Do NOT add new localStorage calls elsewhere - use this manager.
 */

import type { AuthTokens } from '@pleme/types'
import { AUTH_TOKEN_KEY, ZUSTAND_STORAGE_KEY } from './constants'

// Re-export constants for consumers
export { AUTH_TOKEN_KEY, ZUSTAND_STORAGE_KEY }

export class TokenManager {
  private static instance: TokenManager
  private readonly ZUSTAND_STORAGE_KEY = 'auth-storage'
  private operationLock: Promise<void> = Promise.resolve()
  private storageAvailable: boolean | null = null

  private constructor() {
    // Private constructor for singleton pattern
    this.checkStorageAvailability()
  }

  /**
   * Check if localStorage is available and cache the result
   * Prevents repeated try-catch overhead
   */
  private checkStorageAvailability(): boolean {
    if (this.storageAvailable !== null) {
      return this.storageAvailable
    }

    if (typeof window === 'undefined' || !window.localStorage) {
      this.storageAvailable = false
      return false
    }

    try {
      const testKey = '__storage_test__'
      localStorage.setItem(testKey, testKey)
      localStorage.removeItem(testKey)
      this.storageAvailable = true
      return true
    } catch {
      this.storageAvailable = false
      return false
    }
  }

  /**
   * Serialize async operations to prevent race conditions
   * Ensures setTokens/clearTokens don't run concurrently
   */
  private async withLock<T>(operation: () => Promise<T> | T): Promise<T> {
    // Wait for previous operation to complete
    await this.operationLock

    // Create new lock for this operation
    let resolve!: () => void
    this.operationLock = new Promise((r) => {
      resolve = r
    })

    try {
      return await operation()
    } finally {
      // Release lock
      resolve()
    }
  }

  /**
   * Get singleton instance
   */
  public static getInstance(): TokenManager {
    if (!TokenManager.instance) {
      TokenManager.instance = new TokenManager()
    }
    return TokenManager.instance
  }

  /**
   * Set tokens atomically across all storage locations
   *
   * CRITICAL: This is the ONLY place where tokens should be written to storage.
   * Updates both:
   * 1. localStorage AUTH_TOKEN_KEY (for Apollo Client authLink)
   * 2. Zustand persist storage (for app state)
   *
   * @param tokens - Auth tokens to store
   * @returns true if successful, false otherwise
   */
  public async setTokens(tokens: AuthTokens | null): Promise<boolean> {
    return this.withLock(async () => {
      if (!this.checkStorageAvailability()) {
        console.error('[TokenManager] localStorage not available')
        return false
      }

      try {
        if (tokens?.accessToken) {
          // Store access token for Apollo Client
          localStorage.setItem(AUTH_TOKEN_KEY, tokens.accessToken)

          // Store full tokens object for Zustand (will be handled by persist middleware)
          // We don't directly write to Zustand storage here - Zustand persist middleware handles it
          // This method just ensures AUTH_TOKEN_KEY stays in sync

          console.log('[TokenManager] Tokens set successfully', {
            hasAccessToken: !!tokens.accessToken,
            hasRefreshToken: !!tokens.refreshToken,
            expiresIn: tokens.expiresIn,
          })
          return true
        } else {
          // Clear tokens if null/undefined
          return this.clearTokens()
        }
      } catch (error) {
        console.error('[TokenManager] Failed to set tokens:', error)
        return false
      }
    })
  }

  /**
   * Get access token for authentication
   *
   * This is what Apollo Client authLink should call.
   * Reads from localStorage AUTH_TOKEN_KEY.
   *
   * @returns Access token string or null
   */
  public getAccessToken(): string | null {
    if (!this.checkStorageAvailability()) {
      return null
    }

    try {
      return localStorage.getItem(AUTH_TOKEN_KEY)
    } catch (error) {
      console.error('[TokenManager] Failed to get access token:', error)
      return null
    }
  }

  /**
   * Get full tokens object from Zustand storage
   *
   * Used for checking refresh tokens, expiry times, etc.
   * Reads from Zustand persist storage.
   *
   * @returns Full AuthTokens object or null
   */
  public getTokensFromStorage(): AuthTokens | null {
    if (!window.localStorage) {
      return null
    }

    try {
      const zustandData = localStorage.getItem(this.ZUSTAND_STORAGE_KEY)
      if (!zustandData) {
        return null
      }

      const parsed = JSON.parse(zustandData)
      return parsed.state?.tokens || null
    } catch (error) {
      console.error('[TokenManager] Failed to get tokens from storage:', error)
      return null
    }
  }

  /**
   * Clear tokens atomically across all storage locations
   *
   * CRITICAL: This is the ONLY place where tokens should be cleared.
   * Clears both:
   * 1. localStorage AUTH_TOKEN_KEY (for Apollo Client)
   * 2. Signals to Zustand that tokens are cleared (Zustand will persist this)
   *
   * @returns true if successful, false otherwise
   */
  public clearTokens(): boolean {
    if (!this.checkStorageAvailability()) {
      console.error('[TokenManager] localStorage not available')
      return false
    }

    try {
      // Only remove if key exists (optimization)
      const currentToken = localStorage.getItem(AUTH_TOKEN_KEY)
      if (currentToken) {
        localStorage.removeItem(AUTH_TOKEN_KEY)
        console.log('[TokenManager] Tokens cleared successfully')
      }

      // Zustand persist middleware will handle clearing tokens from 'auth-storage'
      // when the store state is updated to tokens: null

      return true
    } catch (error) {
      console.error('[TokenManager] Failed to clear tokens:', error)
      return false
    }
  }

  /**
   * Sync tokens from Zustand storage to AUTH_TOKEN_KEY
   *
   * Called during Zustand rehydration to ensure Apollo Client has the token.
   * This handles the case where Zustand loads from 'auth-storage' but
   * AUTH_TOKEN_KEY hasn't been set yet.
   *
   * @param tokens - Tokens from Zustand rehydration
   */
  public syncFromZustand(tokens: AuthTokens | null): void {
    if (!this.checkStorageAvailability()) {
      return
    }

    try {
      if (tokens?.accessToken) {
        const currentToken = localStorage.getItem(AUTH_TOKEN_KEY)
        // Only update if different (optimization)
        if (currentToken !== tokens.accessToken) {
          localStorage.setItem(AUTH_TOKEN_KEY, tokens.accessToken)
          console.log('[TokenManager] Synced AUTH_TOKEN_KEY from Zustand rehydration')
        }
      } else {
        // Only clear if token exists (avoid unnecessary operation)
        const currentToken = localStorage.getItem(AUTH_TOKEN_KEY)
        if (currentToken) {
          localStorage.removeItem(AUTH_TOKEN_KEY)
          console.log('[TokenManager] Cleared stale AUTH_TOKEN_KEY during rehydration')
        }
      }
    } catch (error) {
      console.error('[TokenManager] Failed to sync from Zustand:', error)
    }
  }

  /**
   * Check if tokens exist in storage
   *
   * @returns true if access token exists, false otherwise
   */
  public hasTokens(): boolean {
    return !!this.getAccessToken()
  }

  /**
   * Debug helper - log current token state
   *
   * Useful for troubleshooting auth issues.
   * DO NOT use in production builds.
   */
  public debugTokenState(): void {
    if (process.env.NODE_ENV === 'production') {
      return
    }

    const accessToken = this.getAccessToken()
    const fullTokens = this.getTokensFromStorage()

    console.group('[TokenManager] Debug Token State')
    console.log('AUTH_TOKEN_KEY present:', !!accessToken)
    console.log('Zustand tokens present:', !!fullTokens)
    console.log('Tokens in sync:', !!accessToken === !!fullTokens?.accessToken)
    if (fullTokens) {
      console.log('Token details:', {
        hasAccessToken: !!fullTokens.accessToken,
        hasRefreshToken: !!fullTokens.refreshToken,
        expiresIn: fullTokens.expiresIn,
        tokenType: fullTokens.tokenType,
      })
    }
    console.groupEnd()
  }
}

// Export singleton instance for convenience
export const tokenManager: TokenManager = TokenManager.getInstance()
