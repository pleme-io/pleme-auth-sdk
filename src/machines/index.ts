/**
 * Auth Machine Exports
 *
 * XState-based authentication state machine
 */

export {
  createAuthMachine,
  getAccessToken,
  setAccessToken,
  registerTokenProvider,
  unregisterTokenProvider,
  type AuthMachine,
  type AuthContext,
  type AuthEvent,
  type AuthLogger,
  type AuthMachineInput,
} from './authMachine'

export {
  type AuthError,
  type AuthErrorCode,
  type LoginOutput,
  type RefreshOutput,
  type CheckAuthOutput,
  type RegisterResult,
  type AuthStateValue,
  type SessionConfig,
  DEFAULT_SESSION_CONFIG,
  isAuthError,
  createAuthError,
} from './authMachine.types'

export {
  useAuthMachine,
  type UseAuthMachineConfig,
  type UseAuthMachineReturn,
} from './useAuthMachine'

// NOTE: authHandlers registry REMOVED (December 2025)
// Apollo now communicates via store.sendEvent({ type: 'APOLLO_AUTH_ERROR' })
// See .claude/skills/authentication-session-architecture.md
