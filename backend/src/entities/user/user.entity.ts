import { PrimaryGeneratedColumn, Column, Entity, OneToMany } from 'typeorm';
import { ApiKey } from '@backend/entities/api-key/api-key.entity';
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
   * Not selected by default to prevent accidental exposure.
   */
  @Column({ select: false })
  passwordHash: string;

  /**
   * Hash of the user's API key, if API access is enabled.
   * Used for authenticating programmatic access.
   */
  @Column({ nullable: true })
  apiKeyHash?: string;

  /**
   * Encrypted secret for two-factor authentication (2FA), e.g., TOTP.
   * Always encrypted before saving to DB. Never expose to clients.
   */
  @Column({ nullable: true })
  twoFaSecret?: string;

  /**
   * Temporary secret for 2FA setup, only stored until verification.
   */
  @Column({ nullable: true })
  pendingTwoFaSecret?: string;

  /**
   * Timestamp of last successful 2FA usage.
   */
  @Column({ type: 'timestamp', nullable: true })
  twoFaLastUsed?: Date;

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

  /**
   * List of API keys associated with the user.
   */
  @OneToMany(() => ApiKey, (apiKey) => apiKey.user)
  apiKeys?: ApiKey[];
}
