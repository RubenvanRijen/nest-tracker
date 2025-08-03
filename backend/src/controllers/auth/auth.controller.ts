import {
  Controller,
  Post,
  Body,
  UsePipes,
  ValidationPipe,
  Get,
  Req,
  UseGuards,
  UnauthorizedException,
  HttpCode,
} from '@nestjs/common';
import { JwtAuthGuard } from '@backend/guards/jwt-auth.guard';
import { RegisterDto } from '@backend/dto/auth/register.dto';
import { LoginDto } from '@backend/dto/auth/login.dto';
import { TwoFactorAuthVerifyDto } from '@backend/dto/auth/twofa-verify.dto';
import { AuthService } from '@backend/services/auth/auth.service';
import type { IAuthRequest } from '@backend/interfaces/auth/IAuthRequest';

@Controller('auth')
@UsePipes(new ValidationPipe({ whitelist: true }))
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  async register(@Body() body: RegisterDto) {
    const user = await this.authService.registerUser(body.email, body.password);
    return {
      email: user.email,
      id: user.id,
      message: 'Registration successful',
    };
  }

  @Post('login')
  async login(@Body() body: LoginDto) {
    const { user, jwt } = await this.authService.loginUser(
      body.email,
      body.password,
      body.token,
    );
    return {
      email: user.email,
      id: user.id,
      token: jwt,
      message: 'Login successful',
    };
  }

  // --- 2FA Endpoints ---

  @UseGuards(JwtAuthGuard)
  @Post('2fa/setup')
  setup2fa(@Req() req: IAuthRequest) {
    const user = req.user;
    const { secret, otpauthUrl } = this.authService.generate2faSecret(
      user.email,
    );
    return { secret, otpauthUrl };
  }

  @UseGuards(JwtAuthGuard)
  @Post('2fa/verify')
  @HttpCode(200)
  async verify2fa(
    @Req() req: IAuthRequest,
    @Body() body: TwoFactorAuthVerifyDto,
  ) {
    const user = req.user;
    const valid = this.authService.verify2faToken(body.secret, body.token);
    if (!valid) {
      throw new UnauthorizedException('Invalid 2FA token');
    }
    user.twoFaSecret = this.authService.encryptSecret(body.secret);
    await this.authService.saveUser(user);
    return { message: '2FA enabled' };
  }

  @UseGuards(JwtAuthGuard)
  @Get('2fa/status')
  twofaStatus(@Req() req: IAuthRequest) {
    const user = req.user;
    return { enabled: !!user.twoFaSecret };
  }
}
