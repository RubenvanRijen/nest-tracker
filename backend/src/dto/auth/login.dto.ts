import {
  IsEmail,
  IsString,
  IsOptional,
  MinLength,
  Matches,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

/**
 * DTO for user login input validation.
 */
export class LoginDto {
  /**
   * User's email address. Must be a valid email format.
   */
  @ApiProperty({
    description: 'User email address',
    example: 'user@example.com',
    format: 'email',
  })
  @IsEmail()
  email: string;

  /**
   * User's password. Must be at least 8 characters and meet complexity requirements.
   */
  @ApiProperty({
    description: 'User password (must meet complexity requirements)',
    example: 'StrongP@ssword123',
    minLength: 8,
  })
  @IsString()
  @MinLength(8)
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]).+$/,
    {
      message:
        'Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character.',
    },
  )
  password: string;

  /**
   * Optional 2FA token for two-factor authentication.
   */
  @ApiProperty({
    description: 'Optional 2FA token for two-factor authentication',
    example: '123456',
    required: false,
  })
  @IsOptional()
  @IsString()
  token?: string;
}
