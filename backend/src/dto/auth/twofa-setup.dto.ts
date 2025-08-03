import { IsEmail } from 'class-validator';

export class TwoFactorAuthSetupDto {
  @IsEmail()
  email: string;
}
