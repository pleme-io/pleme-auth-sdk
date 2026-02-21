/**
 * OAuth Utility Functions
 *
 * Helper functions for Google and Facebook OAuth authentication flows
 */

/**
 * Get Google OAuth Client ID from runtime config
 */
function getGoogleOAuthClientId(): string {
  // Use runtime config (window.ENV) instead of build-time env vars
  return window.ENV?.VITE_GOOGLE_OAUTH_CLIENT_ID || ''
}

/**
 * Get Google OAuth Redirect URI from runtime config
 */
function getGoogleOAuthRedirectUri(): string {
  return window.ENV?.VITE_GOOGLE_OAUTH_REDIRECT_URI || `${window.location.origin}/auth/google/callback`
}

/**
 * Get Facebook OAuth Client ID from runtime config
 */
function getFacebookOAuthClientId(): string {
  // Use runtime config (window.ENV) instead of build-time env vars
  return window.ENV?.VITE_FACEBOOK_OAUTH_CLIENT_ID || ''
}

/**
 * Get Facebook OAuth Redirect URI from runtime config
 */
export function getFacebookOAuthRedirectUri(): string {
  return window.ENV?.VITE_FACEBOOK_OAUTH_REDIRECT_URI || `${window.location.origin}/auth/facebook/callback`
}

/**
 * Generate a random state parameter for OAuth security (CSRF protection)
 */
export function generateOAuthState(): string {
  const array = new Uint8Array(32)
  crypto.getRandomValues(array)
  return Array.from(array, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

/**
 * Build Google OAuth authorization URL
 */
export function getGoogleAuthUrl(state: string, redirectUri?: string): string {
  const params = new URLSearchParams({
    client_id: getGoogleOAuthClientId(),
    redirect_uri: redirectUri || getGoogleOAuthRedirectUri(),
    response_type: 'code',
    scope: 'openid profile email',
    state,
    access_type: 'offline',
    prompt: 'consent',
  })

  return `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`
}

/**
 * Extract OAuth code and state from callback URL
 */
export function parseOAuthCallback(url: string): { code: string; state: string } | null {
  try {
    const params = new URLSearchParams(new URL(url).search)
    const code = params.get('code')
    const state = params.get('state')

    if (!code || !state) {
      return null
    }

    return { code, state }
  } catch (error) {
    console.error('Failed to parse OAuth callback URL:', error)
    return null
  }
}

/**
 * Store OAuth state in sessionStorage for verification
 */
export function storeOAuthState(state: string): void {
  sessionStorage.setItem('google_oauth_state', state)
}

/**
 * Verify OAuth state matches stored value (CSRF protection)
 */
export function verifyOAuthState(state: string): boolean {
  const storedState = sessionStorage.getItem('google_oauth_state')
  sessionStorage.removeItem('google_oauth_state')
  return storedState === state
}

/**
 * Get the redirect URI for OAuth flow
 */
export function getOAuthRedirectUri(): string {
  return getGoogleOAuthRedirectUri()
}

/**
 * Initiate Google OAuth login flow
 * Returns false if OAuth is not configured
 */
export function initiateGoogleOAuth(): boolean {
  const clientId = getGoogleOAuthClientId()
  if (!clientId) {
    console.error('Google OAuth is not configured. Set VITE_GOOGLE_OAUTH_CLIENT_ID in runtime configuration.')
    alert('Google login is not configured. Please contact support or use email/password login.')
    return false
  }

  const state = generateOAuthState()
  storeOAuthState(state)

  const authUrl = getGoogleAuthUrl(state)
  window.location.href = authUrl

  return true
}

// ===== Facebook OAuth Functions =====

/**
 * Build Facebook OAuth authorization URL
 */
export function getFacebookAuthUrl(state: string, redirectUri?: string): string {
  const params = new URLSearchParams({
    client_id: getFacebookOAuthClientId(),
    redirect_uri: redirectUri || getFacebookOAuthRedirectUri(),
    response_type: 'code',
    scope: 'email,public_profile',
    state,
  })

  return `https://www.facebook.com/v18.0/dialog/oauth?${params.toString()}`
}

/**
 * Store Facebook OAuth state in sessionStorage for verification
 */
export function storeFacebookOAuthState(state: string): void {
  sessionStorage.setItem('facebook_oauth_state', state)
}

/**
 * Verify Facebook OAuth state matches stored value (CSRF protection)
 */
export function verifyFacebookOAuthState(state: string | null): boolean {
  if (!state) return false
  const storedState = sessionStorage.getItem('facebook_oauth_state')
  sessionStorage.removeItem('facebook_oauth_state')
  return storedState === state
}

/**
 * Initiate Facebook OAuth login flow
 * Returns false if OAuth is not configured
 */
export function initiateFacebookOAuth(): boolean {
  const clientId = getFacebookOAuthClientId()
  if (!clientId) {
    console.error('Facebook OAuth is not configured. Set VITE_FACEBOOK_OAUTH_CLIENT_ID in runtime configuration.')
    alert('Facebook login is not configured. Please contact support or use email/password login.')
    return false
  }

  const state = generateOAuthState()
  storeFacebookOAuthState(state)

  const authUrl = getFacebookAuthUrl(state)
  window.location.href = authUrl

  return true
}
