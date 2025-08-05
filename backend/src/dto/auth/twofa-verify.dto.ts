import { IsEmail, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

/**
 * DTO for validating two-factor authentication tokens.
 * Used for both 2FA login and enabling 2FA.
 */
export class TwoFactorAuthVerifyDto {
  /**
   * User's email address for identification.
   */
  @ApiProperty({
    description: 'User email address',
    example: 'user@example.com',
    format: 'email',
  })
  @IsEmail()
  email: string;

  /**
   * The time-based one-time password (TOTP) token.
   * Usually a 6-digit code from an authenticator app.
   */
  @ApiProperty({
    description: 'Time-based one-time password (TOTP) token',
    example: '123456',
    minLength: 6,
    maxLength: 6,
  })
  @IsString()
  token: string;
}
