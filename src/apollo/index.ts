/**
 * Apollo Client Auth Integration
 *
 * Provides Apollo Links and utilities for authentication with proper
 * Zanzibar-compliant handling of AuthN vs AuthZ errors.
 *
 * CRITICAL PRINCIPLES:
 * - UNAUTHENTICATED errors trigger token refresh
 * - FORBIDDEN errors do NOT trigger refresh (user IS authenticated)
 * - Auth-exempt operations (Login, Register, RefreshToken) skip Authorization header
 */

// Constants
export {
  AUTH_EXEMPT_OPERATIONS,
  AUTH_ERROR_CODES,
  AUTH_HTTP_STATUS,
  isAuthExemptOperation,
  type AuthExemptOperation,
} from './constants'

// Auth Link
export { createAuthLink, type AuthLinkConfig } from './authLink'

// Error Link (legacy - uses RefreshCoordinator)
export { createErrorLink, type ErrorLinkConfig } from './errorLink'

// Machine Error Link (for XState auth machine integration)
export { createMachineErrorLink, type MachineErrorLinkConfig } from './machineErrorLink'
