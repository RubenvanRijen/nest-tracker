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
import { TwoFaService } from '@backend/services/twofa/twofa.service';
import type { IAuthRequest } from '@backend/interfaces/auth/IAuthRequest';
import { Throttle } from '@nestjs/throttler';

const loginThrottleOptions = {
  default: { limit: 5, ttl: 60000 },
};

const twoFaThrottleOptions = {
  default: { limit: 5, ttl: 60 },
};

@Controller('auth')
@UsePipes(new ValidationPipe({ whitelist: true }))
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly twoFaService: TwoFaService,
  ) {}

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
  @Throttle(loginThrottleOptions)
  async login(@Body() body: LoginDto) {
    const { user } = await this.authService.loginUser(
      body.email,
      body.password,
    );

    if (user.twoFaSecret) {
      return {
        message: 'Two-factor authentication required',
        twoFaEnabled: true,
      };
    }

    const jwt = this.authService.generateJwt(user);
    return {
      email: user.email,
      id: user.id,
      token: jwt,
      message: 'Login successful',
      twoFaEnabled: false,
    };
  }

  @Post('2fa/login')
  @Throttle(twoFaThrottleOptions)
  @HttpCode(200)
  async twoFaLogin(@Body() body: TwoFactorAuthVerifyDto) {
    const user = await this.authService.getUserByEmail(body.email);
    if (!user || !user.twoFaSecret) {
      throw new UnauthorizedException('2FA not enabled for this user');
    }

    const decryptedSecret = this.twoFaService.decryptSecret(user.twoFaSecret);
    const valid = this.twoFaService.verify2faToken(decryptedSecret, body.token);

    if (!valid) {
      throw new UnauthorizedException('Invalid 2FA token');
    }

    const jwt = this.authService.generateJwt(user);
    return {
      email: user.email,
      id: user.id,
      token: jwt,
      message: 'Login successful',
    };
  }

  @UseGuards(JwtAuthGuard)
  @Post('2fa/setup')
  async setup2fa(@Req() req: IAuthRequest) {
    const user = req.user;
    if (!user) throw new UnauthorizedException('User not found');
    const { secret, otpauthUrl } = this.twoFaService.generate2faSecret(
      user.email,
    );
    user.pendingTwoFaSecret = this.twoFaService.encryptSecret(secret);
    await this.authService.saveUser(user);
    return { secret, otpauthUrl };
  }

  @UseGuards(JwtAuthGuard)
  @Post('2fa/enable')
  @Throttle(twoFaThrottleOptions)
  @HttpCode(200)
  async enable2fa(
    @Req() req: IAuthRequest,
    @Body() body: TwoFactorAuthVerifyDto,
  ) {
    const user = req.user;
    if (!user || typeof user.email !== 'string') {
      throw new UnauthorizedException('User not found');
    }
    if (!user.pendingTwoFaSecret) {
      throw new UnauthorizedException('No pending 2FA setup found');
    }
    const decryptedSecret = this.twoFaService.decryptSecret(
      user.pendingTwoFaSecret,
    );
    const valid = this.twoFaService.verify2faToken(decryptedSecret, body.token);
    if (!valid) {
      throw new UnauthorizedException('Invalid 2FA token');
    }
    user.twoFaSecret = user.pendingTwoFaSecret;
    user.pendingTwoFaSecret = undefined;
    await this.authService.saveUser(user);
    return { message: '2FA enabled' };
  }

  @UseGuards(JwtAuthGuard)
  @Get('2fa/status')
  twofaStatus(@Req() req: IAuthRequest) {
    const user = req.user;
    return {
      enabled: !!(user && user.twoFaSecret),
      lastUsed: user?.twoFaLastUsed ?? null,
      pending: !!user?.pendingTwoFaSecret,
    };
  }
}
