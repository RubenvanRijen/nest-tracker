import { IsString, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

/**
 * DTO for verifying a 2FA backup code
 */
export class TwoFactorAuthBackupDto {
  @ApiProperty({
    description: 'User email address',
    example: 'user@example.com',
  })
  @IsString()
  @IsNotEmpty()
  email: string;

  @ApiProperty({
    description: 'Backup code for 2FA authentication',
    example: 'ABCD-1234',
    pattern: '^[A-Z0-9]{4}-[A-Z0-9]{4}$',
  })
  @IsString()
  @IsNotEmpty()
  backupCode: string;
}