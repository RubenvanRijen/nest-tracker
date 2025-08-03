import {
  Controller,
  Post,
  Body,
  UsePipes,
  ValidationPipe,
  Get,
  Req,
  UseGuards,
  BadRequestException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtAuthGuard } from '@backend/guards/jwt-auth.guard';
import { RegisterDto } from '@backend/dto/auth/register.dto';
import { LoginDto } from '@backend/dto/auth/login.dto';
import { TwoFactorAuthVerifyDto } from '@backend/dto/auth/twofa-verify.dto';
import { AuthService } from '@backend/services/auth/auth.service';
import { User } from '@backend/entities/user/user.entity';
import type { Request } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @UsePipes(new ValidationPipe({ whitelist: true }))
  async register(@Body() body: RegisterDto) {
    try {
      const user: User | undefined = await this.authService.registerUser(
        body.email,
        body.password,
      );
      if (!user) {
        return { error: 'Registration failed' };
      }
      return {
        email: user.email,
        id: user.id,
        message: 'Registration successful',
      };
    } catch (err: unknown) {
      return { error: err instanceof Error ? err.message : 'Unknown error' };
    }
  }

  @Post('login')
  async login(@Body() body: LoginDto) {
    try {
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
    } catch (err) {
      if (
        err instanceof BadRequestException ||
        err instanceof UnauthorizedException
      ) {
        throw err;
      }
      throw new BadRequestException('Login failed');
    }
  }

  /**
   * Step 1: 2FA Setup - Generate TOTP secret and otpauth URL
   * POST /auth/2fa/setup { email }
   */
  @UseGuards(JwtAuthGuard)
  @Post('2fa/setup')
  async setup2fa(@Req() req: Request) {
    const user = (req as any).user as User;
    const { secret, otpauthUrl } = this.authService.generate2faSecret(
      user.email,
    );
    return { secret, otpauthUrl };
  }

  /**
   * Step 1: 2FA Verification - Verify TOTP code and enable 2FA
   * POST /auth/2fa/verify { email, token, secret }
   */
  @UseGuards(JwtAuthGuard)
  @Post('2fa/verify')
  async verify2fa(@Req() req: Request, @Body() body: TwoFactorAuthVerifyDto) {
    const user = (req as any).user as User;
    const valid = this.authService.verify2faToken(body.secret, body.token);
    if (!valid) {
      throw new UnauthorizedException('Invalid 2FA token');
    }
    user.twoFaSecret = this.authService.encryptSecret(body.secret);
    await this.authService.saveUser(user);
    return { message: '2FA enabled' };
  }

  /**
   * Step 1: 2FA Status - Check if 2FA is enabled for user
   * GET /auth/2fa/status?email=...
   */
  @UseGuards(JwtAuthGuard)
  @Get('2fa/status')
  async twofaStatus(@Req() req: Request) {
    const user = (req as any).user as User;
    return { enabled: !!user.twoFaSecret };
  }
}
