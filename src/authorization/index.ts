/**
 * Authorization Module (Zanzibar-Compliant)
 *
 * Provides role-based and permission-based access control utilities.
 * Product-agnostic implementation following Google Zanzibar patterns.
 *
 * Key Principles:
 * 1. Users have ARRAYS of roles and permissions (not single values)
 * 2. Permission checking supports wildcards (*, support.*)
 * 3. Role checking supports ANY/ALL matching patterns
 * 4. Pure functions for non-React usage, hooks for React components
 *
 * @example
 * ```tsx
 * // In React components
 * import { useAuthorization } from '@pleme/auth-sdk'
 *
 * const { hasRole, hasPermission } = useAuthorization({
 *   roles: user?.roles,
 *   permissions: user?.permissions,
 * })
 *
 * // In non-React code
 * import { hasPermission, createRoleChecker } from '@pleme/auth-sdk'
 *
 * if (hasPermission(user.permissions, 'admin.users.manage')) {
 *   // Allow operation
 * }
 * ```
 */

// Types
export type {
  AuthorizationUser,
  AuthorizationState,
  RoleCheckConfig,
  PermissionCheckConfig,
} from './types'

// Pure functions for role checking
export {
  hasRole,
  hasAllRoles,
  hasSpecificRole,
  createRoleChecker,
  defineAdminRoles,
} from './roleChecker'

// Pure functions for permission checking
export {
  hasPermission,
  hasAnyPermission,
  hasAllPermissions,
  createPermissionChecker,
} from './permissionChecker'

// React hooks
export {
  useAuthorization,
  createAuthorizationHook,
  type UseAuthorizationConfig,
} from './useAuthorization'
