import { IsString, IsNotEmpty, IsUUID } from 'class-validator';

/**
 * DTO for token refresh requests.
 * Used to validate refresh token input when requesting a new access token.
 */
export class RefreshTokenDto {
  /**
   * The refresh token issued during login or previous refresh.
   * Must be a non-empty string.
   */
  @IsString()
  @IsNotEmpty()
  refreshToken: string;

  /**
   * The user ID associated with the refresh token.
   * Must be a valid UUID.
   */
  @IsUUID()
  @IsNotEmpty()
  userId: string;
}