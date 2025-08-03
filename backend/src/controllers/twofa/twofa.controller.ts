import { Controller, Post, Body, Req, UseGuards } from '@nestjs/common';
import { TwoFaService } from '@backend/services/twofa/twofa.service';
import type { IAuthRequest } from '@backend/interfaces/auth/IAuthRequest';
import { JwtAuthGuard } from '@backend/guards/jwt-auth.guard';

@Controller('2fa')
@UseGuards(JwtAuthGuard)
export class TwoFaController {
  constructor(private readonly twoFaService: TwoFaService) {}

  @Post('generate')
  generate(@Req() req: IAuthRequest, @Body('email') email: string) {
    const userEmail = email || req.user?.email;
    if (!userEmail) throw new Error('User email not found');
    return this.twoFaService.generate2faSecret(userEmail);
  }

  @Post('verify')
  verify(@Body('secret') secret: string, @Body('token') token: string) {
    return { valid: this.twoFaService.verify2faToken(secret, token) };
  }
}
