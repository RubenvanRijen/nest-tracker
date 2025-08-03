import { PrimaryGeneratedColumn, Column, Entity } from 'typeorm';
/**
 * Represents an application user and their authentication credentials.
 * Contains security-related fields for advanced authentication mechanisms.
 */
@Entity()
export class User {
  /**
   * Unique identifier for the user.
   */
  @PrimaryGeneratedColumn('uuid')
  id: string;

  /**
   * User's email address (used for login and notifications).
   */
  @Column({ unique: true })
  email: string;

  /**
   * Hash of the user's password. Never store plain text passwords.
   */
  @Column()
  passwordHash: string;

  /**
   * Hash of the user's API key, if API access is enabled.
   * Used for authenticating programmatic access.
   */
  @Column({ nullable: true })
  apiKeyHash?: string;

  /**
   * Secret for two-factor authentication (2FA), e.g., TOTP.
   * Store securely and never expose to clients.
   */
  /**
   * Encrypted secret for two-factor authentication (2FA), e.g., TOTP.
   * Store securely and never expose to clients.
   * TODO: Implement encryption before saving to DB.
   */
  @Column({ nullable: true })
  twoFaSecret?: string;

  /**
   * Identifier for passkey-based authentication (e.g., WebAuthn).
   * Used for passwordless login and hardware-backed credentials.
   */
  @Column({ nullable: true })
  passkeyId?: string;

  /**
   * List of roles assigned to the user (e.g., admin, user).
   * Used for authorization and access control.
   */
  @Column('simple-array', { nullable: true })
  roles?: string[];
}
