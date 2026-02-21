/**
 * Session expiry warnings
 *
 * Provides user-friendly warnings before session expiration:
 * - Configurable warning thresholds
 * - Multiple warning levels (info, warning, critical)
 * - Customizable notification callbacks
 * - Auto-refresh prompts
 */

import { getTokenExpiryTime, isTokenExpired } from '../utils/jwt';
import type { AuthTokens } from '../types';

/**
 * Warning levels
 */
export enum WarningLevel {
  /** Informational - session will expire soon */
  INFO = 'info',
  /** Warning - session expiring soon, action recommended */
  WARNING = 'warning',
  /** Critical - session about to expire, immediate action required */
  CRITICAL = 'critical',
}

/**
 * Warning event
 */
export interface SessionWarningEvent {
  /** Warning level */
  level: WarningLevel;
  /** Time until expiry in milliseconds */
  timeUntilExpiry: number;
  /** Human-readable message */
  message: string;
  /** Should prompt for refresh */
  promptRefresh: boolean;
}

/**
 * Warning configuration
 */
export interface SessionWarningsConfig {
  /** Show info warning (minutes before expiry, default: 15) */
  infoThresholdMinutes?: number;
  /** Show warning (minutes before expiry, default: 5) */
  warningThresholdMinutes?: number;
  /** Show critical warning (minutes before expiry, default: 1) */
  criticalThresholdMinutes?: number;
  /** Enable warnings (default: true) */
  enabled?: boolean;
  /** Check interval in milliseconds (default: 60000 = 1 minute) */
  checkIntervalMs?: number;
  /** Auto-dismiss warnings after milliseconds (default: 0 = never) */
  autoDismissMs?: number;
}

/**
 * Warning handlers
 */
export interface SessionWarningsHandlers {
  /** Called when warning is triggered */
  onWarning?: (event: SessionWarningEvent) => void;
  /** Called when session has expired */
  onExpired?: () => void;
  /** Called when warning is dismissed */
  onDismiss?: (level: WarningLevel) => void;
}

/**
 * Session warnings manager
 */
export class SessionWarningsManager {
  private config: Required<SessionWarningsConfig>;
  private handlers: SessionWarningsHandlers;
  private checkTimer: number | null = null;
  private lastWarningLevel: WarningLevel | null = null;
  private currentTokens: AuthTokens | null = null;
  private dismissedWarnings = new Set<WarningLevel>();

  constructor(handlers: SessionWarningsHandlers, config: SessionWarningsConfig = {}) {
    this.handlers = handlers;
    this.config = {
      infoThresholdMinutes: config.infoThresholdMinutes ?? 15,
      warningThresholdMinutes: config.warningThresholdMinutes ?? 5,
      criticalThresholdMinutes: config.criticalThresholdMinutes ?? 1,
      enabled: config.enabled ?? true,
      checkIntervalMs: config.checkIntervalMs ?? 60000,
      autoDismissMs: config.autoDismissMs ?? 0,
    };
  }

  /**
   * Start monitoring session
   */
  public start(tokens: AuthTokens): void {
    if (!this.config.enabled) {
      return;
    }

    this.currentTokens = tokens;
    this.dismissedWarnings.clear();
    this.lastWarningLevel = null;

    // Start periodic checks
    this.checkTimer = window.setInterval(() => {
      this.checkExpiry();
    }, this.config.checkIntervalMs);

    // Initial check
    this.checkExpiry();
  }

  /**
   * Stop monitoring
   */
  public stop(): void {
    if (this.checkTimer !== null) {
      window.clearInterval(this.checkTimer);
      this.checkTimer = null;
    }

    this.currentTokens = null;
    this.dismissedWarnings.clear();
    this.lastWarningLevel = null;
  }

  /**
   * Update tokens (e.g., after refresh)
   */
  public updateTokens(tokens: AuthTokens): void {
    this.currentTokens = tokens;
    this.dismissedWarnings.clear();
    this.lastWarningLevel = null;

    // Check immediately with new tokens
    this.checkExpiry();
  }

  /**
   * Check session expiry
   */
  private checkExpiry(): void {
    if (!this.currentTokens) {
      return;
    }

    // Check if access token is already expired
    if (isTokenExpired(this.currentTokens.accessToken)) {
      this.handleExpired();
      return;
    }

    const expiryTime = getTokenExpiryTime(this.currentTokens.accessToken);
    if (!expiryTime) {
      return;
    }

    const now = Date.now();
    const timeUntilExpiry = expiryTime - now;
    const minutesUntilExpiry = timeUntilExpiry / 1000 / 60;

    // Determine warning level
    let level: WarningLevel | null = null;

    if (minutesUntilExpiry <= this.config.criticalThresholdMinutes) {
      level = WarningLevel.CRITICAL;
    } else if (minutesUntilExpiry <= this.config.warningThresholdMinutes) {
      level = WarningLevel.WARNING;
    } else if (minutesUntilExpiry <= this.config.infoThresholdMinutes) {
      level = WarningLevel.INFO;
    }

    // Only show warning if:
    // 1. Level is set (within threshold)
    // 2. Not dismissed
    // 3. Different from last warning (escalation)
    if (level && !this.dismissedWarnings.has(level) && level !== this.lastWarningLevel) {
      this.showWarning(level, timeUntilExpiry);
      this.lastWarningLevel = level;
    }
  }

  /**
   * Show warning
   */
  private showWarning(level: WarningLevel, timeUntilExpiry: number): void {
    const minutes = Math.ceil(timeUntilExpiry / 1000 / 60);

    const event: SessionWarningEvent = {
      level,
      timeUntilExpiry,
      message: this.getWarningMessage(level, minutes),
      promptRefresh: level === WarningLevel.WARNING || level === WarningLevel.CRITICAL,
    };

    this.handlers.onWarning?.(event);

    // Auto-dismiss if configured
    if (this.config.autoDismissMs > 0) {
      setTimeout(() => {
        this.dismiss(level);
      }, this.config.autoDismissMs);
    }
  }

  /**
   * Get warning message
   */
  private getWarningMessage(level: WarningLevel, minutes: number): string {
    switch (level) {
      case WarningLevel.INFO:
        return `Your session will expire in ${minutes} minute${minutes === 1 ? '' : 's'}.`;

      case WarningLevel.WARNING:
        return `Your session will expire in ${minutes} minute${minutes === 1 ? '' : 's'}. Please save your work.`;

      case WarningLevel.CRITICAL:
        return `Your session is about to expire! You will be logged out in ${minutes} minute${minutes === 1 ? '' : 's'}.`;

      default:
        return 'Your session is expiring soon.';
    }
  }

  /**
   * Handle session expired
   */
  private handleExpired(): void {
    this.stop();
    this.handlers.onExpired?.();
  }

  /**
   * Dismiss warning
   */
  public dismiss(level: WarningLevel): void {
    this.dismissedWarnings.add(level);
    this.handlers.onDismiss?.(level);
  }

  /**
   * Dismiss all warnings
   */
  public dismissAll(): void {
    this.dismissedWarnings.add(WarningLevel.INFO);
    this.dismissedWarnings.add(WarningLevel.WARNING);
    this.dismissedWarnings.add(WarningLevel.CRITICAL);
  }

  /**
   * Get time until expiry (in milliseconds)
   */
  public getTimeUntilExpiry(): number | null {
    if (!this.currentTokens) {
      return null;
    }

    const expiryTime = getTokenExpiryTime(this.currentTokens.accessToken);
    if (!expiryTime) {
      return null;
    }

    return Math.max(0, expiryTime - Date.now());
  }

  /**
   * Format time until expiry (human-readable)
   */
  public formatTimeUntilExpiry(): string | null {
    const time = this.getTimeUntilExpiry();
    if (time === null) {
      return null;
    }

    const totalSeconds = Math.floor(time / 1000);
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;

    if (hours > 0) {
      return `${hours}h ${minutes}m`;
    } else if (minutes > 0) {
      return `${minutes}m ${seconds}s`;
    } else {
      return `${seconds}s`;
    }
  }

  /**
   * Check if warning is active for a level
   */
  public isWarningActive(level: WarningLevel): boolean {
    return this.lastWarningLevel === level && !this.dismissedWarnings.has(level);
  }

  /**
   * Get current warning level
   */
  public getCurrentWarningLevel(): WarningLevel | null {
    if (!this.dismissedWarnings.has(this.lastWarningLevel!)) {
      return this.lastWarningLevel;
    }
    return null;
  }
}

/**
 * Create warning notification HTML (for UI integration)
 */
export function createWarningNotification(event: SessionWarningEvent): {
  title: string;
  message: string;
  severity: 'info' | 'warning' | 'error';
  actions: Array<{ label: string; action: 'refresh' | 'dismiss' }>;
} {
  const severity = event.level === WarningLevel.CRITICAL
    ? 'error'
    : event.level === WarningLevel.WARNING
    ? 'warning'
    : 'info';

  const actions: Array<{ label: string; action: 'refresh' | 'dismiss' }> = [];

  if (event.promptRefresh) {
    actions.push({ label: 'Stay Logged In', action: 'refresh' });
  }

  actions.push({ label: 'Dismiss', action: 'dismiss' });

  return {
    title: event.level === WarningLevel.CRITICAL
      ? 'Session Expiring!'
      : event.level === WarningLevel.WARNING
      ? 'Session Expiring Soon'
      : 'Session Expiry Notice',
    message: event.message,
    severity,
    actions,
  };
}
