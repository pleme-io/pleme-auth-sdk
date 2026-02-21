/**
 * WebAuthn and Passkey authentication
 *
 * Enables passwordless authentication using:
 * - Platform authenticators (Face ID, Touch ID, Windows Hello)
 * - Security keys (YubiKey, etc.)
 * - Passkeys (sync across devices via iCloud/Google Password Manager)
 */

/**
 * Credential type
 */
export enum CredentialType {
  /** Platform authenticator (built-in biometric) */
  PLATFORM = 'platform',
  /** Cross-platform authenticator (security key) */
  CROSS_PLATFORM = 'cross-platform',
}

/**
 * WebAuthn registration options
 */
export interface WebAuthnRegistrationOptions {
  /** User ID */
  userId: string;
  /** Username */
  username: string;
  /** Display name */
  displayName: string;
  /** Relying party name (e.g., "NovaSkyn") */
  rpName: string;
  /** Relying party ID (e.g., "novaskyn.com") */
  rpId: string;
  /** Challenge from server (base64url) */
  challenge: string;
  /** Credential type preference */
  authenticatorType?: CredentialType;
  /** Timeout in milliseconds (default: 60000) */
  timeout?: number;
  /** Require user verification (default: "preferred") */
  userVerification?: UserVerificationRequirement;
  /** Attestation preference (default: "none") */
  attestation?: AttestationConveyancePreference;
}

/**
 * WebAuthn authentication options
 */
export interface WebAuthnAuthenticationOptions {
  /** Challenge from server (base64url) */
  challenge: string;
  /** Relying party ID */
  rpId: string;
  /** Allowed credential IDs (base64url) - if empty, any credential can be used */
  allowCredentials?: string[];
  /** Timeout in milliseconds (default: 60000) */
  timeout?: number;
  /** Require user verification (default: "preferred") */
  userVerification?: UserVerificationRequirement;
}

/**
 * Registration result
 */
export interface WebAuthnRegistrationResult {
  /** Credential ID (base64url) */
  credentialId: string;
  /** Public key (base64url) */
  publicKey: string;
  /** Attestation object (base64url) */
  attestationObject: string;
  /** Client data JSON (base64url) */
  clientDataJSON: string;
  /** Authenticator type */
  authenticatorType: CredentialType;
}

/**
 * Authentication result
 */
export interface WebAuthnAuthenticationResult {
  /** Credential ID (base64url) */
  credentialId: string;
  /** Authenticator data (base64url) */
  authenticatorData: string;
  /** Client data JSON (base64url) */
  clientDataJSON: string;
  /** Signature (base64url) */
  signature: string;
  /** User handle (base64url) - may be empty */
  userHandle: string;
}

/**
 * WebAuthn capability check result
 */
export interface WebAuthnCapability {
  /** Browser supports WebAuthn */
  supported: boolean;
  /** Platform authenticator available */
  platformAuthenticatorAvailable: boolean;
  /** Conditional mediation supported (autofill) */
  conditionalMediationSupported: boolean;
}

/**
 * WebAuthn manager
 */
export class WebAuthnManager {
  /**
   * Check WebAuthn capabilities
   */
  public static async checkCapabilities(): Promise<WebAuthnCapability> {
    const supported = typeof window !== 'undefined' &&
      'PublicKeyCredential' in window &&
      typeof window.PublicKeyCredential === 'function';

    if (!supported) {
      return {
        supported: false,
        platformAuthenticatorAvailable: false,
        conditionalMediationSupported: false,
      };
    }

    const platformAuthenticatorAvailable =
      await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();

    const conditionalMediationSupported =
      'isConditionalMediationAvailable' in PublicKeyCredential &&
      typeof PublicKeyCredential.isConditionalMediationAvailable === 'function' &&
      await PublicKeyCredential.isConditionalMediationAvailable();

    return {
      supported,
      platformAuthenticatorAvailable,
      conditionalMediationSupported,
    };
  }

  /**
   * Register new credential (create passkey)
   */
  public static async register(
    options: WebAuthnRegistrationOptions
  ): Promise<WebAuthnRegistrationResult> {
    const capabilities = await this.checkCapabilities();

    if (!capabilities.supported) {
      throw new Error('WebAuthn is not supported in this browser');
    }

    // Convert base64url challenge to ArrayBuffer
    const challenge = this.base64urlToArrayBuffer(options.challenge);

    // Convert user ID to ArrayBuffer
    const userId = new TextEncoder().encode(options.userId);

    // Build credential creation options
    const publicKeyOptions: PublicKeyCredentialCreationOptions = {
      challenge,
      rp: {
        name: options.rpName,
        id: options.rpId,
      },
      user: {
        id: userId,
        name: options.username,
        displayName: options.displayName,
      },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },  // ES256 (recommended)
        { type: 'public-key', alg: -257 }, // RS256
      ],
      authenticatorSelection: {
        authenticatorAttachment: options.authenticatorType === CredentialType.PLATFORM
          ? 'platform'
          : options.authenticatorType === CredentialType.CROSS_PLATFORM
          ? 'cross-platform'
          : undefined,
        userVerification: options.userVerification ?? 'preferred',
        residentKey: 'required', // Enable passkeys
        requireResidentKey: true,
      },
      timeout: options.timeout ?? 60000,
      attestation: options.attestation ?? 'none',
    };

    try {
      const credential = await navigator.credentials.create({
        publicKey: publicKeyOptions,
      }) as PublicKeyCredential;

      if (!credential) {
        throw new Error('Failed to create credential');
      }

      const response = credential.response as AuthenticatorAttestationResponse;

      // Extract credential data
      return {
        credentialId: this.arrayBufferToBase64url(credential.rawId),
        publicKey: this.arrayBufferToBase64url(response.getPublicKey()!),
        attestationObject: this.arrayBufferToBase64url(response.attestationObject),
        clientDataJSON: this.arrayBufferToBase64url(response.clientDataJSON),
        authenticatorType: publicKeyOptions.authenticatorSelection?.authenticatorAttachment === 'platform'
          ? CredentialType.PLATFORM
          : CredentialType.CROSS_PLATFORM,
      };
    } catch (error) {
      if (error instanceof Error) {
        throw new Error(`WebAuthn registration failed: ${error.message}`);
      }
      throw new Error('WebAuthn registration failed');
    }
  }

  /**
   * Authenticate with existing credential (login with passkey)
   */
  public static async authenticate(
    options: WebAuthnAuthenticationOptions
  ): Promise<WebAuthnAuthenticationResult> {
    const capabilities = await this.checkCapabilities();

    if (!capabilities.supported) {
      throw new Error('WebAuthn is not supported in this browser');
    }

    // Convert challenge to ArrayBuffer
    const challenge = this.base64urlToArrayBuffer(options.challenge);

    // Build allowed credentials list
    const allowCredentials = options.allowCredentials?.map((id) => ({
      type: 'public-key' as const,
      id: this.base64urlToArrayBuffer(id),
    }));

    // Build credential request options
    const publicKeyOptions: PublicKeyCredentialRequestOptions = {
      challenge,
      rpId: options.rpId,
      allowCredentials: allowCredentials && allowCredentials.length > 0
        ? allowCredentials
        : undefined, // If empty, allow any credential
      timeout: options.timeout ?? 60000,
      userVerification: options.userVerification ?? 'preferred',
    };

    try {
      const credential = await navigator.credentials.get({
        publicKey: publicKeyOptions,
      }) as PublicKeyCredential;

      if (!credential) {
        throw new Error('Failed to get credential');
      }

      const response = credential.response as AuthenticatorAssertionResponse;

      // Extract authentication data
      return {
        credentialId: this.arrayBufferToBase64url(credential.rawId),
        authenticatorData: this.arrayBufferToBase64url(response.authenticatorData),
        clientDataJSON: this.arrayBufferToBase64url(response.clientDataJSON),
        signature: this.arrayBufferToBase64url(response.signature),
        userHandle: response.userHandle
          ? this.arrayBufferToBase64url(response.userHandle)
          : '',
      };
    } catch (error) {
      if (error instanceof Error) {
        throw new Error(`WebAuthn authentication failed: ${error.message}`);
      }
      throw new Error('WebAuthn authentication failed');
    }
  }

  /**
   * Authenticate with autofill (conditional UI)
   *
   * Shows passkey suggestions in username field autocomplete
   */
  public static async authenticateWithAutofill(
    options: WebAuthnAuthenticationOptions
  ): Promise<WebAuthnAuthenticationResult> {
    const capabilities = await this.checkCapabilities();

    if (!capabilities.conditionalMediationSupported) {
      throw new Error('Conditional mediation (autofill) is not supported');
    }

    const challenge = this.base64urlToArrayBuffer(options.challenge);

    const publicKeyOptions: PublicKeyCredentialRequestOptions = {
      challenge,
      rpId: options.rpId,
      timeout: options.timeout ?? 60000,
      userVerification: options.userVerification ?? 'preferred',
    };

    try {
      const credential = await navigator.credentials.get({
        publicKey: publicKeyOptions,
        mediation: 'conditional', // Enable autofill
      }) as PublicKeyCredential;

      if (!credential) {
        throw new Error('Failed to get credential');
      }

      const response = credential.response as AuthenticatorAssertionResponse;

      return {
        credentialId: this.arrayBufferToBase64url(credential.rawId),
        authenticatorData: this.arrayBufferToBase64url(response.authenticatorData),
        clientDataJSON: this.arrayBufferToBase64url(response.clientDataJSON),
        signature: this.arrayBufferToBase64url(response.signature),
        userHandle: response.userHandle
          ? this.arrayBufferToBase64url(response.userHandle)
          : '',
      };
    } catch (error) {
      if (error instanceof Error) {
        throw new Error(`WebAuthn autofill authentication failed: ${error.message}`);
      }
      throw new Error('WebAuthn autofill authentication failed');
    }
  }

  /**
   * Convert ArrayBuffer to base64url
   */
  private static arrayBufferToBase64url(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  /**
   * Convert base64url to ArrayBuffer
   */
  private static base64urlToArrayBuffer(base64url: string): ArrayBuffer {
    // Convert base64url to base64
    const base64 = base64url
      .replace(/-/g, '+')
      .replace(/_/g, '/');

    // Decode base64
    const binary = atob(base64);

    // Convert to ArrayBuffer
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }

    return bytes.buffer;
  }
}

/**
 * Passkey manager (higher-level wrapper)
 */
export class PasskeyManager {
  private rpName: string;
  private rpId: string;

  constructor(rpName: string, rpId: string) {
    this.rpName = rpName;
    this.rpId = rpId;
  }

  /**
   * Check if passkeys are available
   */
  public async isAvailable(): Promise<boolean> {
    const capabilities = await WebAuthnManager.checkCapabilities();
    return capabilities.supported && capabilities.platformAuthenticatorAvailable;
  }

  /**
   * Register passkey for user
   */
  public async registerPasskey(
    userId: string,
    username: string,
    displayName: string,
    challenge: string
  ): Promise<WebAuthnRegistrationResult> {
    return WebAuthnManager.register({
      userId,
      username,
      displayName,
      rpName: this.rpName,
      rpId: this.rpId,
      challenge,
      authenticatorType: CredentialType.PLATFORM,
      userVerification: 'required',
    });
  }

  /**
   * Login with passkey
   */
  public async loginWithPasskey(challenge: string): Promise<WebAuthnAuthenticationResult> {
    return WebAuthnManager.authenticate({
      challenge,
      rpId: this.rpId,
      userVerification: 'required',
    });
  }

  /**
   * Login with passkey autofill
   */
  public async loginWithPasskeyAutofill(challenge: string): Promise<WebAuthnAuthenticationResult> {
    return WebAuthnManager.authenticateWithAutofill({
      challenge,
      rpId: this.rpId,
      userVerification: 'required',
    });
  }

  /**
   * Check if autofill is available
   */
  public async isAutofillAvailable(): Promise<boolean> {
    const capabilities = await WebAuthnManager.checkCapabilities();
    return capabilities.conditionalMediationSupported;
  }
}
