/**
 * Authorization Types (Zanzibar-Compliant)
 *
 * Types for role-based and permission-based access control.
 * Follows Google Zanzibar pattern with arrays of roles and aggregated permissions.
 */

/**
 * User with authorization context
 */
export interface AuthorizationUser {
  /** User's roles array (Zanzibar pattern: users have MULTIPLE roles) */
  roles?: string[]
  /** User's aggregated permissions array */
  permissions?: string[]
}

/**
 * Configuration for role checking
 */
export interface RoleCheckConfig {
  /** User's current roles */
  userRoles: string[]
  /** Roles to check against */
  requiredRoles: string[]
}

/**
 * Configuration for permission checking
 */
export interface PermissionCheckConfig {
  /** User's current permissions */
  userPermissions: string[]
  /** Permission to check */
  permission: string
}

/**
 * Authorization state returned by useAuthorization hook
 */
export interface AuthorizationState<TRole extends string = string> {
  /** User's roles array */
  roles: TRole[]
  /** User's permissions array */
  permissions: string[]
  /** Check if user has ANY of the specified roles */
  hasRole: (requiredRoles: TRole[]) => boolean
  /** Check if user has ALL of the specified roles */
  hasAllRoles: (requiredRoles: TRole[]) => boolean
  /** Check if user has the specified permission (supports wildcards) */
  hasPermission: (permission: string) => boolean
  /** Check if user has ANY of the specified permissions */
  hasAnyPermission: (permissions: string[]) => boolean
  /** Check if user has ALL of the specified permissions */
  hasAllPermissions: (permissions: string[]) => boolean
}
