import { IsEmail, IsString, MinLength, Matches } from 'class-validator';

/**
 * DTO for user registration input validation.
 */
export class RegisterDto {
  /**
   * User's email address. Must be a valid email format.
   */
  @IsEmail()
  email: string;

  /**
   * User's password. Must be at least 8 characters.
   */
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
}
