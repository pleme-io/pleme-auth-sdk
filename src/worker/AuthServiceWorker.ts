/**
 * Service Worker integration for authentication
 *
 * Enables:
 * - Background token refresh
 * - Offline token validation
 * - Session persistence across app restarts
 */

import type { AuthTokens } from '../types';
import { isTokenExpired, getTokenExpiryTime } from '../utils/jwt';

/**
 * Service worker message types
 */
export enum WorkerMessageType {
  /** Register auth state with service worker */
  REGISTER_AUTH = 'register_auth',
  /** Unregister auth state (logout) */
  UNREGISTER_AUTH = 'unregister_auth',
  /** Request token refresh */
  REFRESH_TOKEN = 'refresh_token',
  /** Token refresh completed */
  REFRESH_COMPLETE = 'refresh_complete',
  /** Token refresh failed */
  REFRESH_FAILED = 'refresh_failed',
  /** Get current auth state */
  GET_AUTH_STATE = 'get_auth_state',
  /** Auth state response */
  AUTH_STATE_RESPONSE = 'auth_state_response',
  /** Schedule token refresh */
  SCHEDULE_REFRESH = 'schedule_refresh',
  /** Cancel scheduled refresh */
  CANCEL_REFRESH = 'cancel_refresh',
}

/**
 * Service worker message
 */
export interface WorkerMessage {
  type: WorkerMessageType;
  payload?: unknown;
}

/**
 * Register auth message payload
 */
export interface RegisterAuthPayload {
  tokens: AuthTokens;
  refreshUrl: string;
}

/**
 * Refresh complete message payload
 */
export interface RefreshCompletePayload {
  tokens: AuthTokens;
}

/**
 * Auth state response payload
 */
export interface AuthStatePayload {
  isAuthenticated: boolean;
  tokens: AuthTokens | null;
}

/**
 * Service worker manager for authentication
 */
export class AuthServiceWorkerManager {
  private registration: ServiceWorkerRegistration | null = null;
  private messageHandlers = new Map<WorkerMessageType, (payload: unknown) => void>();

  /**
   * Initialize service worker
   */
  public async initialize(scriptUrl: string): Promise<boolean> {
    if (typeof window === 'undefined' || !('serviceWorker' in navigator)) {
      console.warn('Service Worker not supported');
      return false;
    }

    try {
      this.registration = await navigator.serviceWorker.register(scriptUrl);

      // Listen for messages from service worker
      navigator.serviceWorker.addEventListener('message', this.handleMessage.bind(this));

      console.log('Service Worker registered successfully');
      return true;
    } catch (error) {
      console.error('Service Worker registration failed:', error);
      return false;
    }
  }

  /**
   * Handle messages from service worker
   */
  private handleMessage(event: MessageEvent<WorkerMessage>): void {
    const { type, payload } = event.data;
    const handler = this.messageHandlers.get(type);

    if (handler) {
      handler(payload);
    }
  }

  /**
   * Register message handler
   */
  public on(type: WorkerMessageType, handler: (payload: unknown) => void): void {
    this.messageHandlers.set(type, handler);
  }

  /**
   * Send message to service worker
   */
  private async sendMessage(message: WorkerMessage): Promise<void> {
    if (!this.registration?.active) {
      console.warn('Service Worker not active, cannot send message');
      return;
    }

    this.registration.active.postMessage(message);
  }

  /**
   * Register authentication state with service worker
   */
  public async registerAuth(tokens: AuthTokens, refreshUrl: string): Promise<void> {
    await this.sendMessage({
      type: WorkerMessageType.REGISTER_AUTH,
      payload: { tokens, refreshUrl } satisfies RegisterAuthPayload,
    });

    // Schedule automatic refresh
    await this.scheduleTokenRefresh(tokens);
  }

  /**
   * Unregister authentication (logout)
   */
  public async unregisterAuth(): Promise<void> {
    await this.sendMessage({
      type: WorkerMessageType.UNREGISTER_AUTH,
    });
  }

  /**
   * Request token refresh
   */
  public async refreshToken(): Promise<void> {
    await this.sendMessage({
      type: WorkerMessageType.REFRESH_TOKEN,
    });
  }

  /**
   * Get current auth state from service worker
   */
  public async getAuthState(): Promise<AuthStatePayload | null> {
    return new Promise((resolve) => {
      // Set up one-time listener for response
      const handler = (payload: unknown) => {
        this.messageHandlers.delete(WorkerMessageType.AUTH_STATE_RESPONSE);
        resolve(payload as AuthStatePayload);
      };

      this.on(WorkerMessageType.AUTH_STATE_RESPONSE, handler);

      // Request state
      this.sendMessage({
        type: WorkerMessageType.GET_AUTH_STATE,
      });

      // Timeout after 5 seconds
      setTimeout(() => {
        this.messageHandlers.delete(WorkerMessageType.AUTH_STATE_RESPONSE);
        resolve(null);
      }, 5000);
    });
  }

  /**
   * Schedule token refresh before expiry
   */
  private async scheduleTokenRefresh(tokens: AuthTokens): Promise<void> {
    const expiryTime = getTokenExpiryTime(tokens.accessToken);
    if (!expiryTime) {
      return;
    }

    // Schedule refresh 5 minutes before expiry
    const refreshTime = expiryTime - Date.now() - 5 * 60 * 1000;

    if (refreshTime > 0) {
      await this.sendMessage({
        type: WorkerMessageType.SCHEDULE_REFRESH,
        payload: { refreshTime },
      });
    }
  }

  /**
   * Cancel scheduled refresh
   */
  public async cancelScheduledRefresh(): Promise<void> {
    await this.sendMessage({
      type: WorkerMessageType.CANCEL_REFRESH,
    });
  }

  /**
   * Unregister service worker
   */
  public async unregister(): Promise<void> {
    if (this.registration) {
      await this.registration.unregister();
      this.registration = null;
    }
  }

  /**
   * Check if service worker is ready
   */
  public isReady(): boolean {
    return this.registration?.active !== null && this.registration?.active !== undefined;
  }
}

/**
 * Service worker script content
 *
 * This should be compiled into a separate worker file.
 * Below is the implementation that should run inside the service worker context.
 */
export const SERVICE_WORKER_SCRIPT = `
// Service Worker for authentication management
// This runs in the service worker context

let authState = {
  isAuthenticated: false,
  tokens: null,
  refreshUrl: null,
};

let refreshTimer = null;

// Handle messages from main thread
self.addEventListener('message', async (event) => {
  const { type, payload } = event.data;

  switch (type) {
    case 'register_auth':
      handleRegisterAuth(payload);
      break;

    case 'unregister_auth':
      handleUnregisterAuth();
      break;

    case 'refresh_token':
      await handleRefreshToken();
      break;

    case 'get_auth_state':
      handleGetAuthState(event.source);
      break;

    case 'schedule_refresh':
      handleScheduleRefresh(payload.refreshTime);
      break;

    case 'cancel_refresh':
      handleCancelRefresh();
      break;
  }
});

function handleRegisterAuth(payload) {
  authState = {
    isAuthenticated: true,
    tokens: payload.tokens,
    refreshUrl: payload.refreshUrl,
  };
  console.log('[SW] Auth registered');
}

function handleUnregisterAuth() {
  authState = {
    isAuthenticated: false,
    tokens: null,
    refreshUrl: null,
  };
  handleCancelRefresh();
  console.log('[SW] Auth unregistered');
}

async function handleRefreshToken() {
  if (!authState.isAuthenticated || !authState.refreshUrl) {
    return;
  }

  try {
    const response = await fetch(authState.refreshUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        refreshToken: authState.tokens.refreshToken,
      }),
    });

    if (response.ok) {
      const data = await response.json();
      authState.tokens = data.tokens;

      // Notify all clients
      const clients = await self.clients.matchAll();
      clients.forEach(client => {
        client.postMessage({
          type: 'refresh_complete',
          payload: { tokens: data.tokens },
        });
      });

      console.log('[SW] Token refreshed successfully');
    } else {
      // Refresh failed
      const clients = await self.clients.matchAll();
      clients.forEach(client => {
        client.postMessage({
          type: 'refresh_failed',
          payload: { error: 'Token refresh failed' },
        });
      });

      console.error('[SW] Token refresh failed');
    }
  } catch (error) {
    console.error('[SW] Token refresh error:', error);
  }
}

function handleGetAuthState(source) {
  source.postMessage({
    type: 'auth_state_response',
    payload: {
      isAuthenticated: authState.isAuthenticated,
      tokens: authState.tokens,
    },
  });
}

function handleScheduleRefresh(refreshTime) {
  handleCancelRefresh();

  refreshTimer = setTimeout(async () => {
    await handleRefreshToken();
  }, refreshTime);

  console.log('[SW] Token refresh scheduled in', refreshTime, 'ms');
}

function handleCancelRefresh() {
  if (refreshTimer) {
    clearTimeout(refreshTimer);
    refreshTimer = null;
    console.log('[SW] Token refresh cancelled');
  }
}

// Install event
self.addEventListener('install', (event) => {
  console.log('[SW] Installing...');
  self.skipWaiting();
});

// Activate event
self.addEventListener('activate', (event) => {
  console.log('[SW] Activating...');
  event.waitUntil(self.clients.claim());
});

// Fetch event - can be used for offline support
self.addEventListener('fetch', (event) => {
  // Add offline caching logic here if needed
});
`;

/**
 * Generate service worker file
 *
 * Call this during build to create the service worker file
 */
export function generateServiceWorkerFile(): string {
  return SERVICE_WORKER_SCRIPT;
}
