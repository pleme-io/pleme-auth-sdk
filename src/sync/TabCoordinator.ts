/**
 * Multi-tab session coordination
 *
 * Synchronizes authentication state across browser tabs using BroadcastChannel API.
 * Prevents duplicate token refreshes and ensures consistent logout across all tabs.
 */

import type { AuthTokens } from '../types';

/**
 * Message types for cross-tab communication
 */
export enum TabMessageType {
  /** Tokens were refreshed in another tab */
  TOKENS_REFRESHED = 'tokens_refreshed',
  /** User logged out in another tab */
  LOGOUT = 'logout',
  /** User logged in in another tab */
  LOGIN = 'login',
  /** Token refresh is in progress (lock) */
  REFRESH_LOCK = 'refresh_lock',
  /** Token refresh completed (unlock) */
  REFRESH_UNLOCK = 'refresh_unlock',
  /** Heartbeat to detect tab closures */
  HEARTBEAT = 'heartbeat',
  /** Request current auth state */
  STATE_REQUEST = 'state_request',
  /** Response with current auth state */
  STATE_RESPONSE = 'state_response',
}

/**
 * Message payload structure
 */
export interface TabMessage {
  type: TabMessageType;
  timestamp: number;
  tabId: string;
  payload?: unknown;
}

/**
 * Tokens refreshed message payload
 */
export interface TokensRefreshedPayload {
  tokens: AuthTokens;
}

/**
 * State response payload
 */
export interface StateResponsePayload {
  isAuthenticated: boolean;
  tokens: AuthTokens | null;
}

/**
 * Refresh lock payload
 */
export interface RefreshLockPayload {
  lockId: string;
}

/**
 * Tab coordinator options
 */
export interface TabCoordinatorOptions {
  /** Channel name (default: 'auth-sync') */
  channelName?: string;
  /** Heartbeat interval in ms (default: 5000) */
  heartbeatInterval?: number;
  /** Enable debug logging (default: false) */
  debug?: boolean;
}

/**
 * Event handlers for tab coordinator
 */
export interface TabCoordinatorHandlers {
  /** Called when tokens are refreshed in another tab */
  onTokensRefreshed?: (tokens: AuthTokens) => void;
  /** Called when user logs out in another tab */
  onLogout?: () => void;
  /** Called when user logs in in another tab */
  onLogin?: (tokens: AuthTokens) => void;
  /** Called when refresh lock is requested */
  onRefreshLockRequested?: (lockId: string, tabId: string) => void;
  /** Called when refresh lock is released */
  onRefreshLockReleased?: (lockId: string, tabId: string) => void;
  /** Called when state is requested from another tab */
  onStateRequested?: (requestingTabId: string) => StateResponsePayload | null;
}

/**
 * Tab coordinator for cross-tab authentication synchronization
 */
export class TabCoordinator {
  private channel: BroadcastChannel | null = null;
  private tabId: string;
  private heartbeatTimer: number | null = null;
  private options: Required<TabCoordinatorOptions>;
  private handlers: TabCoordinatorHandlers;
  private activeTabs = new Set<string>();
  private refreshLock: { lockId: string; tabId: string } | null = null;

  constructor(handlers: TabCoordinatorHandlers, options: TabCoordinatorOptions = {}) {
    this.tabId = this.generateTabId();
    this.handlers = handlers;
    this.options = {
      channelName: options.channelName ?? 'auth-sync',
      heartbeatInterval: options.heartbeatInterval ?? 5000,
      debug: options.debug ?? false,
    };

    this.initialize();
  }

  /**
   * Generate unique tab ID
   */
  private generateTabId(): string {
    return `tab-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
  }

  /**
   * Initialize the coordinator
   */
  private initialize(): void {
    if (typeof window === 'undefined' || !('BroadcastChannel' in window)) {
      this.log('BroadcastChannel not supported, tab coordination disabled');
      return;
    }

    try {
      this.channel = new BroadcastChannel(this.options.channelName);
      this.channel.onmessage = this.handleMessage.bind(this);
      this.startHeartbeat();
      this.log('Tab coordinator initialized', this.tabId);

      // Request state from other tabs
      this.sendMessage(TabMessageType.STATE_REQUEST, {});
    } catch (error) {
      console.error('Failed to initialize tab coordinator:', error);
    }
  }

  /**
   * Handle incoming messages
   */
  private handleMessage(event: MessageEvent<TabMessage>): void {
    const message = event.data;

    // Ignore messages from self
    if (message.tabId === this.tabId) {
      return;
    }

    this.log('Received message', message.type, 'from', message.tabId);

    switch (message.type) {
      case TabMessageType.TOKENS_REFRESHED:
        this.handleTokensRefreshed(message.payload as TokensRefreshedPayload);
        break;

      case TabMessageType.LOGOUT:
        this.handleLogout();
        break;

      case TabMessageType.LOGIN:
        this.handleLogin(message.payload as TokensRefreshedPayload);
        break;

      case TabMessageType.REFRESH_LOCK:
        this.handleRefreshLock(message.payload as RefreshLockPayload, message.tabId);
        break;

      case TabMessageType.REFRESH_UNLOCK:
        this.handleRefreshUnlock(message.payload as RefreshLockPayload, message.tabId);
        break;

      case TabMessageType.HEARTBEAT:
        this.handleHeartbeat(message.tabId);
        break;

      case TabMessageType.STATE_REQUEST:
        this.handleStateRequest(message.tabId);
        break;

      case TabMessageType.STATE_RESPONSE:
        this.handleStateResponse(message.payload as StateResponsePayload);
        break;
    }
  }

  /**
   * Handle tokens refreshed message
   */
  private handleTokensRefreshed(payload: TokensRefreshedPayload): void {
    this.log('Tokens refreshed in another tab');
    this.handlers.onTokensRefreshed?.(payload.tokens);
  }

  /**
   * Handle logout message
   */
  private handleLogout(): void {
    this.log('Logout detected in another tab');
    this.handlers.onLogout?.();
  }

  /**
   * Handle login message
   */
  private handleLogin(payload: TokensRefreshedPayload): void {
    this.log('Login detected in another tab');
    this.handlers.onLogin?.(payload.tokens);
  }

  /**
   * Handle refresh lock request
   */
  private handleRefreshLock(payload: RefreshLockPayload, tabId: string): void {
    this.log('Refresh lock requested', payload.lockId, 'by', tabId);
    this.refreshLock = { lockId: payload.lockId, tabId };
    this.handlers.onRefreshLockRequested?.(payload.lockId, tabId);
  }

  /**
   * Handle refresh lock release
   */
  private handleRefreshUnlock(payload: RefreshLockPayload, tabId: string): void {
    this.log('Refresh lock released', payload.lockId, 'by', tabId);
    if (this.refreshLock?.lockId === payload.lockId) {
      this.refreshLock = null;
    }
    this.handlers.onRefreshLockReleased?.(payload.lockId, tabId);
  }

  /**
   * Handle heartbeat
   */
  private handleHeartbeat(tabId: string): void {
    this.activeTabs.add(tabId);
  }

  /**
   * Handle state request
   */
  private handleStateRequest(requestingTabId: string): void {
    this.log('State requested by', requestingTabId);
    const state = this.handlers.onStateRequested?.(requestingTabId);
    if (state) {
      this.sendMessage(TabMessageType.STATE_RESPONSE, state);
    }
  }

  /**
   * Handle state response
   */
  private handleStateResponse(payload: StateResponsePayload): void {
    this.log('Received state response', payload.isAuthenticated);
    if (payload.isAuthenticated && payload.tokens) {
      this.handlers.onLogin?.(payload.tokens);
    }
  }

  /**
   * Send message to all tabs
   */
  private sendMessage(type: TabMessageType, payload: unknown): void {
    if (!this.channel) {
      return;
    }

    const message: TabMessage = {
      type,
      timestamp: Date.now(),
      tabId: this.tabId,
      payload,
    };

    this.log('Sending message', type);
    this.channel.postMessage(message);
  }

  /**
   * Start heartbeat
   */
  private startHeartbeat(): void {
    this.heartbeatTimer = window.setInterval(() => {
      this.sendMessage(TabMessageType.HEARTBEAT, {});
    }, this.options.heartbeatInterval);
  }

  /**
   * Stop heartbeat
   */
  private stopHeartbeat(): void {
    if (this.heartbeatTimer !== null) {
      window.clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  /**
   * Notify other tabs that tokens were refreshed
   */
  public notifyTokensRefreshed(tokens: AuthTokens): void {
    this.sendMessage(TabMessageType.TOKENS_REFRESHED, { tokens } satisfies TokensRefreshedPayload);
  }

  /**
   * Notify other tabs that user logged out
   */
  public notifyLogout(): void {
    this.sendMessage(TabMessageType.LOGOUT, {});
  }

  /**
   * Notify other tabs that user logged in
   */
  public notifyLogin(tokens: AuthTokens): void {
    this.sendMessage(TabMessageType.LOGIN, { tokens } satisfies TokensRefreshedPayload);
  }

  /**
   * Request refresh lock (returns true if lock acquired)
   */
  public async requestRefreshLock(): Promise<string | null> {
    if (!this.channel) {
      // No coordination available, grant lock
      return this.generateLockId();
    }

    // Check if another tab already has the lock
    if (this.refreshLock && this.refreshLock.tabId !== this.tabId) {
      this.log('Refresh lock held by another tab', this.refreshLock.tabId);
      return null;
    }

    // Acquire lock
    const lockId = this.generateLockId();
    this.refreshLock = { lockId, tabId: this.tabId };
    this.sendMessage(TabMessageType.REFRESH_LOCK, { lockId } satisfies RefreshLockPayload);

    return lockId;
  }

  /**
   * Release refresh lock
   */
  public releaseRefreshLock(lockId: string): void {
    if (this.refreshLock?.lockId === lockId && this.refreshLock.tabId === this.tabId) {
      this.sendMessage(TabMessageType.REFRESH_UNLOCK, { lockId } satisfies RefreshLockPayload);
      this.refreshLock = null;
      this.log('Refresh lock released', lockId);
    }
  }

  /**
   * Generate lock ID
   */
  private generateLockId(): string {
    return `lock-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
  }

  /**
   * Get active tab count (including self)
   */
  public getActiveTabCount(): number {
    return this.activeTabs.size + 1; // +1 for current tab
  }

  /**
   * Check if this is the only active tab
   */
  public isOnlyTab(): boolean {
    return this.getActiveTabCount() === 1;
  }

  /**
   * Get tab ID
   */
  public getTabId(): string {
    return this.tabId;
  }

  /**
   * Cleanup
   */
  public destroy(): void {
    this.stopHeartbeat();
    this.channel?.close();
    this.channel = null;
    this.log('Tab coordinator destroyed');
  }

  /**
   * Debug logging
   */
  private log(...args: unknown[]): void {
    if (this.options.debug) {
      console.log('[TabCoordinator]', ...args);
    }
  }
}
