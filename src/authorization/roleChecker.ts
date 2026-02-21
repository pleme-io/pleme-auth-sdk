/**
 * Role Checker Utilities (Zanzibar-Compliant)
 *
 * Pure functions for checking user roles.
 * Product-agnostic implementation following Google Zanzibar patterns.
 *
 * Key Principle: Users have an ARRAY of roles, not a single role.
 * This follows the Zanzibar pattern where a user can have multiple
 * relationships (roles) to different resources.
 *
 * @example
 * ```ts
 * import { hasRole, hasAllRoles } from '@pleme/auth-sdk'
 *
 * // Check if user has ANY of the required roles
 * if (hasRole(user.roles, ['admin', 'superadmin'])) {
 *   // User is an admin
 * }
 *
 * // Check if user has ALL required roles
 * if (hasAllRoles(user.roles, ['verified', 'premium'])) {
 *   // User is both verified AND premium
 * }
 * ```
 */

/**
 * Check if user has ANY of the specified roles
 *
 * Zanzibar pattern: A user matches if they have at least ONE of the required roles.
 * Empty requiredRoles array = always returns true (no roles required).
 *
 * @param userRoles - Array of user's current roles
 * @param requiredRoles - Roles to check against (ANY match = true)
 * @returns true if user has at least one of the required roles
 */
export function hasRole<T extends string = string>(
  userRoles: T[],
  requiredRoles: T[]
): boolean {
  if (!requiredRoles || requiredRoles.length === 0) return true
  if (!userRoles || userRoles.length === 0) return false
  return userRoles.some((userRole) => requiredRoles.includes(userRole))
}

/**
 * Check if user has ALL of the specified roles
 *
 * Use when multiple roles are required simultaneously.
 * Empty requiredRoles array = always returns true.
 *
 * @param userRoles - Array of user's current roles
 * @param requiredRoles - Roles to check against (ALL must match)
 * @returns true if user has all of the required roles
 */
export function hasAllRoles<T extends string = string>(
  userRoles: T[],
  requiredRoles: T[]
): boolean {
  if (!requiredRoles || requiredRoles.length === 0) return true
  if (!userRoles || userRoles.length === 0) return false
  return requiredRoles.every((required) => userRoles.includes(required))
}

/**
 * Check if user has a specific role
 *
 * @param userRoles - Array of user's current roles
 * @param role - Single role to check
 * @returns true if user has the role
 */
export function hasSpecificRole<T extends string = string>(
  userRoles: T[],
  role: T
): boolean {
  if (!userRoles || userRoles.length === 0) return false
  return userRoles.includes(role)
}

/**
 * Role checker interface
 */
export interface RoleChecker<T extends string = string> {
  /** Check if user has ANY of the roles */
  hasAny: (requiredRoles: T[]) => boolean
  /** Check if user has ALL of the roles */
  hasAll: (requiredRoles: T[]) => boolean
  /** Check if user has a specific role */
  has: (role: T) => boolean
  /** Raw roles array */
  roles: T[]
}

/**
 * Create a role checker bound to a user's roles
 *
 * @param userRoles - Array of user's current roles
 * @returns Object with role checking methods
 *
 * @example
 * ```ts
 * const checker = createRoleChecker(user.roles)
 * if (checker.hasAny(['admin', 'superadmin'])) {
 *   // User is an admin
 * }
 * ```
 */
export function createRoleChecker<T extends string = string>(userRoles: T[]): RoleChecker<T> {
  return {
    hasAny: (requiredRoles: T[]): boolean => hasRole(userRoles, requiredRoles),
    hasAll: (requiredRoles: T[]): boolean => hasAllRoles(userRoles, requiredRoles),
    has: (role: T): boolean => hasSpecificRole(userRoles, role),
    roles: userRoles,
  }
}

/**
 * Define a set of admin roles for a product
 *
 * @param roles - Array of role strings that grant admin access
 * @returns Function to check if user is admin
 *
 * @example
 * ```ts
 * const ADMIN_ROLES = ['superadmin', 'admin', 'staff'] as const
 * const isAdmin = defineAdminRoles(ADMIN_ROLES)
 *
 * if (isAdmin(user.roles)) {
 *   // User has admin access
 * }
 * ```
 */
export function defineAdminRoles<T extends string>(roles: readonly T[]) {
  return (userRoles: string[]): boolean => {
    return hasRole(userRoles as T[], [...roles])
  }
}
