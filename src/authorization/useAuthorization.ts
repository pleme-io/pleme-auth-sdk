/**
 * useAuthorization Hook (Zanzibar-Compliant)
 *
 * React hook for role-based and permission-based access control.
 * Product-agnostic implementation - products configure their own role definitions.
 *
 * @example
 * ```tsx
 * import { useAuthorization } from '@pleme/auth-sdk'
 *
 * function AdminPage() {
 *   const { hasRole, hasPermission, roles } = useAuthorization({
 *     roles: user?.roles,
 *     permissions: user?.permissions,
 *   })
 *
 *   if (!hasRole(['admin', 'superadmin'])) {
 *     return <AccessDenied />
 *   }
 *
 *   if (!hasPermission('users.manage')) {
 *     return <ReadOnlyView />
 *   }
 *
 *   return <AdminDashboard />
 * }
 * ```
 */

import { useMemo } from 'react'
import { hasRole, hasAllRoles } from './roleChecker'
import { hasPermission, hasAnyPermission, hasAllPermissions } from './permissionChecker'
import type { AuthorizationState, AuthorizationUser } from './types'

/**
 * Configuration for useAuthorization hook
 */
export interface UseAuthorizationConfig<TRole extends string = string> {
  /** User's roles array (from auth context) */
  roles?: TRole[]
  /** User's permissions array (from auth context) */
  permissions?: string[]
}

/**
 * Hook for Zanzibar-compliant authorization
 *
 * Provides memoized role and permission checking functions.
 * All checks follow Zanzibar patterns (arrays, not single values).
 *
 * @param config - User's roles and permissions from auth context
 * @returns Authorization state with checking functions
 */
export function useAuthorization<TRole extends string = string>(
  config: UseAuthorizationConfig<TRole>
): AuthorizationState<TRole> {
  const { roles: configRoles, permissions: configPermissions } = config

  // Memoize the roles array
  const roles = useMemo<TRole[]>(() => {
    return configRoles || []
  }, [configRoles])

  // Memoize the permissions array
  const permissions = useMemo<string[]>(() => {
    return configPermissions || []
  }, [configPermissions])

  // Memoize role checking functions
  const hasRoleFn = useMemo(() => {
    return (requiredRoles: TRole[]): boolean => {
      return hasRole(roles, requiredRoles)
    }
  }, [roles])

  const hasAllRolesFn = useMemo(() => {
    return (requiredRoles: TRole[]): boolean => {
      return hasAllRoles(roles, requiredRoles)
    }
  }, [roles])

  // Memoize permission checking functions
  const hasPermissionFn = useMemo(() => {
    return (permission: string): boolean => {
      return hasPermission(permissions, permission)
    }
  }, [permissions])

  const hasAnyPermissionFn = useMemo(() => {
    return (requiredPermissions: string[]): boolean => {
      return hasAnyPermission(permissions, requiredPermissions)
    }
  }, [permissions])

  const hasAllPermissionsFn = useMemo(() => {
    return (requiredPermissions: string[]): boolean => {
      return hasAllPermissions(permissions, requiredPermissions)
    }
  }, [permissions])

  return {
    roles,
    permissions,
    hasRole: hasRoleFn,
    hasAllRoles: hasAllRolesFn,
    hasPermission: hasPermissionFn,
    hasAnyPermission: hasAnyPermissionFn,
    hasAllPermissions: hasAllPermissionsFn,
  }
}

/**
 * Return type for product authorization hook
 */
export interface ProductAuthorizationState<TRole extends string = string>
  extends AuthorizationState<TRole> {
  /** Whether user has any admin role (as defined by product) */
  isAdmin: boolean
  /** The user object passed to the hook */
  user: AuthorizationUser | null | undefined
}

/**
 * Create a product-specific authorization hook
 *
 * Use this to define admin roles and create a typed hook for your product.
 *
 * @param adminRoles - Array of roles that grant admin access
 * @returns Hook factory that includes product-specific helpers
 *
 * @example
 * ```ts
 * // In your product's auth config
 * import { createAuthorizationHook } from '@pleme/auth-sdk'
 *
 * const ADMIN_ROLES = ['superadmin', 'admin', 'staff'] as const
 * type AdminRole = typeof ADMIN_ROLES[number]
 *
 * export const useProductAuth = createAuthorizationHook(ADMIN_ROLES)
 *
 * // Usage
 * const { isAdmin, hasRole } = useProductAuth(user)
 * ```
 */
export function createAuthorizationHook<TRole extends string>(
  adminRoles: readonly TRole[]
): (user: AuthorizationUser | null | undefined) => ProductAuthorizationState<TRole> {
  return function useProductAuthorization(
    user: AuthorizationUser | null | undefined
  ): ProductAuthorizationState<TRole> {
    const base = useAuthorization<TRole>({
      roles: user?.roles as TRole[],
      permissions: user?.permissions,
    })

    // Add product-specific helpers
    const isAdmin = useMemo((): boolean => {
      return hasRole(base.roles, [...adminRoles])
    }, [base.roles])

    return {
      roles: base.roles,
      permissions: base.permissions,
      hasRole: base.hasRole,
      hasAllRoles: base.hasAllRoles,
      hasPermission: base.hasPermission,
      hasAnyPermission: base.hasAnyPermission,
      hasAllPermissions: base.hasAllPermissions,
      isAdmin,
      user,
    }
  }
}
