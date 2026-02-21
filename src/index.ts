/**
 * @pleme/auth-sdk - Comprehensive Authentication SDK
 *
 * Single source of truth for all authentication logic across Nexus products.
 * Implements Zanzibar-compliant AuthN/AuthZ patterns.
 *
 * ARCHITECTURE (v2 - XState):
 * - AuthMachine: XState finite state machine for deterministic auth flows
 * - useAuthMachine: React hook for machine integration
 * - In-memory tokens: No localStorage (XSS safe, no stale token issues)
 * - HttpOnly cookies: Refresh tokens managed by server
 *
 * @see .claude/skills/authentication-jwt-graphql for full documentation
 */

// XState Auth Machine (NEW - recommended)
export {
  createAuthMachine,
  getAccessToken,
  setAccessToken,
  registerTokenProvider,
  unregisterTokenProvider,
  useAuthMachine,
  type AuthMachine,
  type AuthContext,
  type AuthEvent,
  type AuthLogger,
  type AuthMachineInput,
  type AuthError,
  type AuthErrorCode,
  type LoginOutput,
  type RefreshOutput,
  type CheckAuthOutput,
  type RegisterResult,
  type AuthStateValue,
  type UseAuthMachineConfig,
  type UseAuthMachineReturn,
  // WORLD-CLASS SESSION HANDLING: Export session configuration
  type SessionConfig,
  DEFAULT_SESSION_CONFIG,
  isAuthError,
  createAuthError,
  // NOTE: authHandlers registry REMOVED (December 2025)
  // Apollo now communicates via store.sendEvent({ type: 'APOLLO_AUTH_ERROR' })
  // See .claude/skills/authentication-session-architecture.md
} from './machines'

// XState + Zustand Unified Store (NEW - recommended)
// This is the canonical way to use auth: XState coordinates, Zustand adapts for React
export {
  createAuthMachineStore,
  type AuthMachineState,
  type AuthMachineStoreConfig,
} from './store/authMachineStore'

// Core authentication (legacy - use createAuthMachineStore instead)
// Note: getAccessToken is exported from machines, not from authStore
export {
  createAuthStore,
  type AuthState,
  type AuthStoreConfig,
  type Logger,
} from './store/authStore'
export * from './token/TokenManager'

// Token refresh coordination (legacy - handled by machine)
export * from './refresh'

// Apollo Client integration (Zanzibar-compliant error handling)
export * from './apollo'

// React hooks
export * from './hooks'

// Utilities
export * from './utils/jwt'
export * from './utils/oauth'

// Multi-tab coordination (legacy - to be removed)
export * from './sync/TabCoordinator'

// Auth state synchronization (legacy - replaced by machine)
export * from './sync/AuthStateSync'

// Service worker integration
export * from './worker/AuthServiceWorker'

// Session warnings
export * from './warnings/SessionWarnings'

// Activity detection
export * from './activity/ActivityDetector'

// WebAuthn and Passkeys
export * from './webauthn/WebAuthnManager'

// Authorization (Zanzibar-compliant role/permission checking)
export * from './authorization'

// Types
export * from './types'
