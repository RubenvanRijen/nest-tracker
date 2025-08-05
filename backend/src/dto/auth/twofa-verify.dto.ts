import { IsEmail, IsString } from 'class-validator';

/**
 * DTO for validating two-factor authentication tokens.
 * Used for both 2FA login and enabling 2FA.
 */
export class TwoFactorAuthVerifyDto {
  /**
   * User's email address for identification.
   */
  @IsEmail()
  email: string;

  /**
   * The time-based one-time password (TOTP) token.
   * Usually a 6-digit code from an authenticator app.
   */
  @IsString()
  token: string;
}
