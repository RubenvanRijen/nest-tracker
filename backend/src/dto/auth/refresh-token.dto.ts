import { IsString, IsNotEmpty, IsUUID } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

/**
 * DTO for token refresh requests.
 * Used to validate refresh token input when requesting a new access token.
 */
export class RefreshTokenDto {
  /**
   * The refresh token issued during login or previous refresh.
   * Must be a non-empty string.
   */
  @ApiProperty({
    description: 'Refresh token received during login or previous refresh',
    example: '6fd8d272-375a-4d8f-b7a3-248db6c56b48',
  })
  @IsString()
  @IsNotEmpty()
  refreshToken: string;

  /**
   * The user ID associated with the refresh token.
   * Must be a valid UUID.
   */
  @ApiProperty({
    description: 'User ID associated with the refresh token',
    example: '123e4567-e89b-12d3-a456-426614174000',
    format: 'uuid',
  })
  @IsUUID()
  @IsNotEmpty()
  userId: string;
}
