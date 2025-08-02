import { IsEmail, IsString, MinLength } from 'class-validator';

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
  password: string;
}
