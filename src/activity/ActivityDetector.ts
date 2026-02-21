/**
 * User activity detection
 *
 * Detects user activity to enable:
 * - Idle timeout detection
 * - Auto-session extension
 * - Activity-based security policies
 */

/**
 * Activity types that can be tracked
 */
export enum ActivityEventType {
  /** Mouse movement */
  MOUSE_MOVE = 'mousemove',
  /** Mouse click */
  MOUSE_CLICK = 'click',
  /** Keyboard input */
  KEYBOARD = 'keydown',
  /** Scroll event */
  SCROLL = 'scroll',
  /** Touch event (mobile) */
  TOUCH = 'touchstart',
  /** Focus event */
  FOCUS = 'focus',
  /** Visibility change */
  VISIBILITY = 'visibilitychange',
}

/**
 * Activity event
 */
export interface ActivityEvent {
  /** Event type */
  type: ActivityEventType;
  /** Timestamp */
  timestamp: number;
}

/**
 * Activity detector configuration
 */
export interface ActivityDetectorConfig {
  /** Events to track (default: all) */
  trackedEvents?: ActivityEventType[];
  /** Idle timeout in milliseconds (default: 1800000 = 30 minutes) */
  idleTimeoutMs?: number;
  /** Throttle interval for activity tracking (default: 5000 = 5 seconds) */
  throttleMs?: number;
  /** Enable debug logging (default: false) */
  debug?: boolean;
}

/**
 * Activity detector handlers
 */
export interface ActivityDetectorHandlers {
  /** Called when user becomes active after being idle */
  onActive?: () => void;
  /** Called when user becomes idle */
  onIdle?: () => void;
  /** Called on any activity (throttled) */
  onActivity?: (event: ActivityEvent) => void;
}

/**
 * Activity detector
 */
export class ActivityDetector {
  private config: Required<ActivityDetectorConfig>;
  private handlers: ActivityDetectorHandlers;
  private lastActivityTime: number;
  private isIdle = false;
  private idleCheckTimer: number | null = null;
  private throttleTimer: number | null = null;
  private eventListeners: Array<{ event: string; handler: EventListener }> = [];
  private activityQueue: ActivityEvent[] = [];

  constructor(handlers: ActivityDetectorHandlers, config: ActivityDetectorConfig = {}) {
    this.handlers = handlers;
    this.config = {
      trackedEvents: config.trackedEvents ?? [
        ActivityEventType.MOUSE_MOVE,
        ActivityEventType.MOUSE_CLICK,
        ActivityEventType.KEYBOARD,
        ActivityEventType.SCROLL,
        ActivityEventType.TOUCH,
        ActivityEventType.FOCUS,
        ActivityEventType.VISIBILITY,
      ],
      idleTimeoutMs: config.idleTimeoutMs ?? 1800000, // 30 minutes
      throttleMs: config.throttleMs ?? 5000, // 5 seconds
      debug: config.debug ?? false,
    };

    this.lastActivityTime = Date.now();
  }

  /**
   * Start detecting activity
   */
  public start(): void {
    if (typeof window === 'undefined') {
      return;
    }

    // Register event listeners
    this.config.trackedEvents.forEach((eventType) => {
      const handler = this.handleActivity.bind(this, eventType);
      const domEvent = this.getDOMEvent(eventType);

      window.addEventListener(domEvent, handler, { passive: true });
      this.eventListeners.push({ event: domEvent, handler });

      this.log('Registered listener for', eventType);
    });

    // Start idle check timer
    this.idleCheckTimer = window.setInterval(() => {
      this.checkIdle();
    }, 60000); // Check every minute

    // Start activity throttle timer
    this.startThrottle();

    this.log('Activity detector started');
  }

  /**
   * Stop detecting activity
   */
  public stop(): void {
    // Remove event listeners
    this.eventListeners.forEach(({ event, handler }) => {
      window.removeEventListener(event, handler);
    });
    this.eventListeners = [];

    // Clear timers
    if (this.idleCheckTimer !== null) {
      window.clearInterval(this.idleCheckTimer);
      this.idleCheckTimer = null;
    }

    if (this.throttleTimer !== null) {
      window.clearTimeout(this.throttleTimer);
      this.throttleTimer = null;
    }

    this.log('Activity detector stopped');
  }

  /**
   * Handle activity event
   */
  private handleActivity(type: ActivityEventType, _event: Event): void {
    const now = Date.now();
    this.lastActivityTime = now;

    // Add to activity queue
    this.activityQueue.push({
      type,
      timestamp: now,
    });

    // If was idle, trigger active callback
    if (this.isIdle) {
      this.isIdle = false;
      this.handlers.onActive?.();
      this.log('User is now active');
    }
  }

  /**
   * Start activity throttle
   */
  private startThrottle(): void {
    this.throttleTimer = window.setTimeout(() => {
      this.processActivityQueue();
      this.startThrottle(); // Restart timer
    }, this.config.throttleMs);
  }

  /**
   * Process queued activities
   */
  private processActivityQueue(): void {
    if (this.activityQueue.length === 0) {
      return;
    }

    // Get most recent activity
    const lastActivity = this.activityQueue[this.activityQueue.length - 1];

    // Notify handler
    this.handlers.onActivity?.(lastActivity);

    // Clear queue
    this.activityQueue = [];

    this.log('Processed activity queue:', lastActivity.type);
  }

  /**
   * Check if user is idle
   */
  private checkIdle(): void {
    const now = Date.now();
    const timeSinceActivity = now - this.lastActivityTime;

    if (!this.isIdle && timeSinceActivity >= this.config.idleTimeoutMs) {
      this.isIdle = true;
      this.handlers.onIdle?.();
      this.log('User is now idle');
    }
  }

  /**
   * Get DOM event name from activity type
   */
  private getDOMEvent(type: ActivityEventType): string {
    return type.toString();
  }

  /**
   * Get last activity time
   */
  public getLastActivityTime(): number {
    return this.lastActivityTime;
  }

  /**
   * Get time since last activity (in milliseconds)
   */
  public getTimeSinceActivity(): number {
    return Date.now() - this.lastActivityTime;
  }

  /**
   * Check if currently idle
   */
  public isCurrentlyIdle(): boolean {
    return this.isIdle;
  }

  /**
   * Manually mark as active (e.g., after background tab returns to foreground)
   */
  public markActive(): void {
    this.lastActivityTime = Date.now();
    if (this.isIdle) {
      this.isIdle = false;
      this.handlers.onActive?.();
      this.log('Manually marked as active');
    }
  }

  /**
   * Manually mark as idle
   */
  public markIdle(): void {
    if (!this.isIdle) {
      this.isIdle = true;
      this.handlers.onIdle?.();
      this.log('Manually marked as idle');
    }
  }

  /**
   * Get time until idle (in milliseconds)
   */
  public getTimeUntilIdle(): number {
    const timeSinceActivity = this.getTimeSinceActivity();
    return Math.max(0, this.config.idleTimeoutMs - timeSinceActivity);
  }

  /**
   * Format time until idle (human-readable)
   */
  public formatTimeUntilIdle(): string {
    const ms = this.getTimeUntilIdle();
    const totalSeconds = Math.floor(ms / 1000);
    const minutes = Math.floor(totalSeconds / 60);
    const seconds = totalSeconds % 60;

    if (minutes > 0) {
      return `${minutes}m ${seconds}s`;
    } else {
      return `${seconds}s`;
    }
  }

  /**
   * Debug logging
   */
  private log(...args: unknown[]): void {
    if (this.config.debug) {
      console.log('[ActivityDetector]', ...args);
    }
  }
}

/**
 * Page visibility detector
 *
 * Separate utility for detecting when page becomes visible/hidden
 */
export class PageVisibilityDetector {
  private handlers: {
    onVisible?: () => void;
    onHidden?: () => void;
  };

  constructor(handlers: { onVisible?: () => void; onHidden?: () => void }) {
    this.handlers = handlers;
  }

  /**
   * Start detecting visibility changes
   */
  public start(): void {
    if (typeof document === 'undefined') {
      return;
    }

    document.addEventListener('visibilitychange', this.handleVisibilityChange.bind(this));
  }

  /**
   * Stop detecting
   */
  public stop(): void {
    if (typeof document === 'undefined') {
      return;
    }

    document.removeEventListener('visibilitychange', this.handleVisibilityChange.bind(this));
  }

  /**
   * Handle visibility change
   */
  private handleVisibilityChange(): void {
    if (document.hidden) {
      this.handlers.onHidden?.();
    } else {
      this.handlers.onVisible?.();
    }
  }

  /**
   * Check if page is currently visible
   */
  public isVisible(): boolean {
    if (typeof document === 'undefined') {
      return true;
    }

    return !document.hidden;
  }
}
