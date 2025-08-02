import { Controller, Post, Body } from '@nestjs/common';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  async register(@Body() body: { email: string; password: string }) {
    // TODO: Save user to DB
    const hash = await this.authService.hashPassword(body.password);
    return { email: body.email, passwordHash: hash };
  }
}
