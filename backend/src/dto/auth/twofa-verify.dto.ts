import { IsEmail, IsString } from 'class-validator';

export class TwoFactorAuthVerifyDto {
  @IsEmail()
  email: string;

  @IsString()
  token: string;

  @IsString()
  secret: string;
}
