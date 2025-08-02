/**
 * Represents an application user and their authentication credentials.
 * Contains security-related fields for advanced authentication mechanisms.
 */
export class User {
  /**
   * Unique identifier for the user.
   */
  id: string;

  /**
   * User's email address (used for login and notifications).
   */
  email: string;

  /**
   * Hash of the user's password. Never store plain text passwords.
   */
  passwordHash: string;

  /**
   * Hash of the user's API key, if API access is enabled.
   * Used for authenticating programmatic access.
   */
  apiKeyHash?: string;

  /**
   * Secret for two-factor authentication (2FA), e.g., TOTP.
   * Store securely and never expose to clients.
   */
  twoFaSecret?: string;

  /**
   * Identifier for passkey-based authentication (e.g., WebAuthn).
   * Used for passwordless login and hardware-backed credentials.
   */
  passkeyId?: string;

  /**
   * List of roles assigned to the user (e.g., admin, user).
   * Used for authorization and access control.
   */
  roles?: string[];
}
