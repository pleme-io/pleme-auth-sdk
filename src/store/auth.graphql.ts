/**
 * Authentication GraphQL Operations
 *
 * Mutations and queries for authentication functionality
 */

import { gql } from '@apollo/client'
import type { DocumentNode } from '@apollo/client'

/**
 * Login mutation
 * Authenticates user with email and password
 */
export const LOGIN_MUTATION: DocumentNode = gql`
  mutation Login($input: LoginInput!) {
    login(input: $input) {
      user {
        id
        email
        displayName
        username
        avatarUrl
        roles
        permissions
        status
        emailVerified
        secondaryEmail
        secondaryEmailVerified
        mfaEnabled
      }
      accessToken
      refreshToken
      expiresIn
      sessionId
    }
  }
`

/**
 * Register mutation
 * Creates new user account with Brazilian-specific fields
 */
export const REGISTER_MUTATION: DocumentNode = gql`
  mutation Register($input: RegisterInput!) {
    register(input: $input) {
      user {
        id
        email
        displayName
        username
        avatarUrl
        roles
        status
        emailVerified
        mfaEnabled
      }
      verificationRequired
      message
    }
  }
`

/**
 * Refresh token mutation
 * Exchanges refresh token for new access token AND rotated refresh token
 *
 * NOTE: refreshToken parameter is OPTIONAL when AUTH_COOKIES_ENABLED=true on backend.
 * When cookies are enabled, the backend reads the refresh token from HttpOnly cookie.
 * The frontend should pass null/undefined to use cookie-based refresh.
 *
 * IMPORTANT: Backend rotates refresh tokens on each use for security (token rotation).
 * The frontend MUST capture and store the new refreshToken, or subsequent
 * refresh attempts will fail with "Invalid token" error.
 */
export const REFRESH_TOKEN_MUTATION: DocumentNode = gql`
  mutation RefreshToken($refreshToken: String) {
    refreshToken(refreshToken: $refreshToken) {
      accessToken
      refreshToken
      expiresIn
    }
  }
`

/**
 * Logout mutation
 * Ends user session
 */
export const LOGOUT_MUTATION: DocumentNode = gql`
  mutation Logout($sessionId: String!) {
    logout(sessionId: $sessionId)
  }
`

/**
 * Update user profile mutation
 * Updates authenticated user's profile information
 */
export const UPDATE_PROFILE_MUTATION: DocumentNode = gql`
  mutation UpdateProfile($input: UpdateProfileInput!) {
    updateProfile(input: $input) {
      id
      email
      displayName
      username
      avatarUrl
      firstName
      lastName
      cpf
      phoneNumber
      status
      emailVerified
      secondaryEmail
      secondaryEmailVerified
      mfaEnabled
      createdAt
      updatedAt
    }
  }
`

/**
 * Current user query
 * Fetches authenticated user information with all profile fields
 */
export const ME_QUERY: DocumentNode = gql`
  query Me {
    me {
      id
      email
      displayName
      username
      avatarUrl
      roles
      permissions
      firstName
      lastName
      cpf
      phoneNumber
      status
      emailVerified
      secondaryEmail
      secondaryEmailVerified
      mfaEnabled
      createdAt
      updatedAt
    }
  }
`

// Type definitions for better TypeScript support
export interface LoginInput {
  email: string
  cpf: string
  password: string
  mfaCode?: string
  rememberMe?: boolean
  deviceId?: string
}

export interface RegisterInput {
  email: string
  password: string
  username?: string // Optional: backend auto-generates if not provided
  displayName: string
  firstName?: string
  lastName?: string
  cpf?: string
  phoneNumber?: string
  confirmPassword: string
  termsAccepted: boolean
  referralCode?: string
}

export interface LoginResponse {
  login: {
    user: {
      id: string
      email: string
      displayName?: string
      username?: string
      avatarUrl?: string
      roles: string[]
      permissions: string[]
      status: 'ACTIVE' | 'LOCKED' | 'SUSPENDED' | 'PENDING_VERIFICATION' | 'DELETED'
      emailVerified: boolean
      mfaEnabled: boolean
    }
    accessToken: string
    refreshToken: string
    expiresIn: number
    sessionId: string
  }
}

export interface RegisterResponse {
  register: {
    user: {
      id: string
      email: string
      displayName?: string
      username?: string
      avatarUrl?: string
      roles: string[]
      status: 'ACTIVE' | 'LOCKED' | 'SUSPENDED' | 'PENDING_VERIFICATION' | 'DELETED'
      emailVerified: boolean
      mfaEnabled: boolean
    }
    verificationRequired: boolean
    message: string
  }
}

export interface RefreshTokenResponse {
  refreshToken: {
    accessToken: string
    refreshToken: string
    expiresIn: number
  }
}

export interface MeResponse {
  me: {
    id: string
    email: string
    displayName?: string
    username?: string
    avatarUrl?: string
    roles: string[]
    permissions: string[]
    firstName?: string
    lastName?: string
    cpf?: string
    phoneNumber?: string
    status: 'ACTIVE' | 'LOCKED' | 'SUSPENDED' | 'PENDING_VERIFICATION' | 'DELETED'
    emailVerified: boolean
    secondaryEmail?: string
    secondaryEmailVerified: boolean
    mfaEnabled: boolean
    createdAt: string
    updatedAt: string
  }
}

export interface UpdateProfileInput {
  displayName?: string
  avatarUrl?: string
  firstName?: string
  lastName?: string
  phoneNumber?: string
}

export interface UpdateProfileResponse {
  updateProfile: {
    id: string
    email: string
    displayName?: string
    username?: string
    avatarUrl?: string
    firstName?: string
    lastName?: string
    cpf?: string
    phoneNumber?: string
    status: 'ACTIVE' | 'LOCKED' | 'SUSPENDED' | 'PENDING_VERIFICATION' | 'DELETED'
    emailVerified: boolean
    mfaEnabled: boolean
    createdAt: string
    updatedAt: string
  }
}

export interface SecondaryEmailResponse {
  id: string
  email: string
  secondaryEmail?: string
  secondaryEmailVerified: boolean
}

export interface AddSecondaryEmailResponse {
  addSecondaryEmail: SecondaryEmailResponse
}

export interface VerifySecondaryEmailResponse {
  verifySecondaryEmail: SecondaryEmailResponse
}

export interface SetPrimaryEmailResponse {
  setPrimaryEmail: SecondaryEmailResponse
}

export interface RemoveSecondaryEmailResponse {
  removeSecondaryEmail: SecondaryEmailResponse
}

/**
 * Add secondary email mutation
 * Adds a secondary email to the authenticated user's account
 */
export const ADD_SECONDARY_EMAIL_MUTATION: DocumentNode = gql`
  mutation AddSecondaryEmail($email: String!) {
    addSecondaryEmail(email: $email) {
      id
      email
      secondaryEmail
      secondaryEmailVerified
    }
  }
`

/**
 * Verify secondary email mutation
 * Verifies the secondary email using the token sent via email
 */
export const VERIFY_SECONDARY_EMAIL_MUTATION: DocumentNode = gql`
  mutation VerifySecondaryEmail($userId: String!, $token: String!) {
    verifySecondaryEmail(userId: $userId, token: $token) {
      id
      email
      secondaryEmail
      secondaryEmailVerified
    }
  }
`

/**
 * Set primary email mutation
 * Swaps primary and secondary emails (requires verified secondary email)
 */
export const SET_PRIMARY_EMAIL_MUTATION: DocumentNode = gql`
  mutation SetPrimaryEmail($useSecondary: Boolean!) {
    setPrimaryEmail(useSecondary: $useSecondary) {
      id
      email
      secondaryEmail
      secondaryEmailVerified
    }
  }
`

/**
 * Remove secondary email mutation
 * Removes the secondary email from the authenticated user's account
 */
export const REMOVE_SECONDARY_EMAIL_MUTATION: DocumentNode = gql`
  mutation RemoveSecondaryEmail {
    removeSecondaryEmail {
      id
      email
      secondaryEmail
      secondaryEmailVerified
    }
  }
`
