/**
 * Permission Checker Utilities (Zanzibar-Compliant)
 *
 * Pure functions for checking user permissions with wildcard support.
 * Product-agnostic implementation following Google Zanzibar patterns.
 *
 * @example
 * ```ts
 * import { hasPermission, hasAnyPermission } from '@pleme/auth-sdk'
 *
 * // Check single permission
 * if (hasPermission(user.permissions, 'support.tickets.read')) {
 *   // User can read tickets
 * }
 *
 * // Wildcard matching
 * // If user has 'support.*', they match 'support.tickets.read'
 * // If user has '*', they match everything
 * ```
 */

/**
 * Check if user has a specific permission
 *
 * Supports wildcard matching:
 * - '*' or '*.*' matches ALL permissions
 * - 'support.*' matches any permission starting with 'support.'
 *
 * @param userPermissions - Array of user's permissions
 * @param permission - Permission to check
 * @returns true if user has the permission (exact or wildcard match)
 */
export function hasPermission(userPermissions: string[], permission: string): boolean {
  if (!userPermissions || userPermissions.length === 0) return false

  // Check for wildcard permissions first (superadmin pattern)
  if (userPermissions.includes('*') || userPermissions.includes('*.*')) {
    return true
  }

  // Check exact match
  if (userPermissions.includes(permission)) {
    return true
  }

  // Check prefix wildcard (e.g., "support.*" matches "support.tickets.read")
  const permissionParts = permission.split('.')
  for (let i = permissionParts.length - 1; i > 0; i--) {
    const wildcardPermission = permissionParts.slice(0, i).join('.') + '.*'
    if (userPermissions.includes(wildcardPermission)) {
      return true
    }
  }

  return false
}

/**
 * Check if user has ANY of the specified permissions
 *
 * @param userPermissions - Array of user's permissions
 * @param requiredPermissions - Permissions to check (ANY match = true)
 * @returns true if user has at least one of the permissions
 */
export function hasAnyPermission(
  userPermissions: string[],
  requiredPermissions: string[]
): boolean {
  if (!requiredPermissions || requiredPermissions.length === 0) return true
  return requiredPermissions.some((perm) => hasPermission(userPermissions, perm))
}

/**
 * Check if user has ALL of the specified permissions
 *
 * @param userPermissions - Array of user's permissions
 * @param requiredPermissions - Permissions to check (ALL must match)
 * @returns true if user has all of the permissions
 */
export function hasAllPermissions(
  userPermissions: string[],
  requiredPermissions: string[]
): boolean {
  if (!requiredPermissions || requiredPermissions.length === 0) return true
  return requiredPermissions.every((perm) => hasPermission(userPermissions, perm))
}

/**
 * Permission checker interface
 */
export interface PermissionChecker {
  /** Check single permission */
  has: (permission: string) => boolean
  /** Check if user has ANY of the permissions */
  hasAny: (permissions: string[]) => boolean
  /** Check if user has ALL of the permissions */
  hasAll: (permissions: string[]) => boolean
  /** Raw permissions array */
  permissions: string[]
}

/**
 * Create a permission checker bound to a user's permissions
 *
 * @param userPermissions - Array of user's permissions
 * @returns Object with permission checking methods
 *
 * @example
 * ```ts
 * const checker = createPermissionChecker(user.permissions)
 * if (checker.has('support.tickets.read')) {
 *   // User can read tickets
 * }
 * ```
 */
export function createPermissionChecker(userPermissions: string[]): PermissionChecker {
  return {
    has: (permission: string): boolean => hasPermission(userPermissions, permission),
    hasAny: (permissions: string[]): boolean => hasAnyPermission(userPermissions, permissions),
    hasAll: (permissions: string[]): boolean => hasAllPermissions(userPermissions, permissions),
    permissions: userPermissions,
  }
}
