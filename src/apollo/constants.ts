/**
 * Apollo Auth Constants
 *
 * Constants and utilities for authentication in Apollo Client.
 * Follows Zanzibar principles for AuthN vs AuthZ separation.
 */

/**
 * Operations that should NOT include the Authorization header.
 *
 * Per Zanzibar separation of concerns:
 * - RefreshToken: Uses refresh token in body, not (possibly expired) access token
 * - Login: User is authenticating, no token exists yet
 * - Register: User is creating account, no token exists yet
 *
 * CRITICAL: Sending an expired access token with these operations can cause
 * the backend to reject them based on the invalid header before processing
 * the body. This leads to the dreaded "refresh loop" bug.
 */
export const AUTH_EXEMPT_OPERATIONS = ['RefreshToken', 'Login', 'Register'] as const

export type AuthExemptOperation = (typeof AUTH_EXEMPT_OPERATIONS)[number]

/**
 * Check if an operation should skip the Authorization header
 *
 * @param operationName - GraphQL operation name
 * @returns true if the operation should not include Authorization header
 */
export function isAuthExemptOperation(operationName: string | undefined): boolean {
  return operationName !== undefined && AUTH_EXEMPT_OPERATIONS.includes(operationName as AuthExemptOperation)
}

/**
 * GraphQL error codes that indicate authentication failure
 *
 * CRITICAL Zanzibar Distinction:
 * - UNAUTHENTICATED: "I don't know who you are" → should trigger token refresh
 * - FORBIDDEN: "I know who you are, but you lack permission" → show error, DON'T refresh
 *
 * Only UNAUTHENTICATED should trigger token refresh. FORBIDDEN means the user
 * IS authenticated but simply doesn't have permission for that operation.
 */
export const AUTH_ERROR_CODES = {
  /** User is not authenticated - should trigger token refresh */
  UNAUTHENTICATED: 'UNAUTHENTICATED',
  /** User is authenticated but lacks permission - do NOT refresh */
  FORBIDDEN: 'FORBIDDEN',
} as const

/**
 * HTTP status codes for authentication errors
 */
export const AUTH_HTTP_STATUS = {
  /** 401 - User not authenticated */
  UNAUTHORIZED: 401,
  /** 403 - User authenticated but forbidden */
  FORBIDDEN: 403,
} as const
