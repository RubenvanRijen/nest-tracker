import { IsEmail, IsString, MinLength, Matches } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { PASSWORD_COMPLEXITY_REGEX } from '@backend/constants/auth';

/**
 * DTO for user registration input validation.
 */
export class RegisterDto {
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
   * User's password. Must be at least 8 characters.
   */
  @ApiProperty({
    description: 'User password (must meet complexity requirements)',
    example: 'StrongP@ssword123',
    minLength: 8,
  })
  @IsString()
  @MinLength(8)
  @Matches(PASSWORD_COMPLEXITY_REGEX, {
    message:
      'Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character.',
  })
  password: string;
}
