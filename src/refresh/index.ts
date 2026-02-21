/**
 * Refresh module - Token refresh coordination
 *
 * Provides race-condition-proof token refresh for:
 * - Apollo Client error handling
 * - Scheduled background refresh
 * - Visibility-based refresh
 * - Rehydration refresh
 */

export {
  refreshCoordinator,
  RefreshCoordinatorImpl,
  type RefreshResult,
  type RefreshStats,
  type RefreshCallback,
} from './RefreshCoordinator'
