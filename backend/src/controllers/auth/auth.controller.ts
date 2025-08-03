import {
  Controller,
  Post,
  Body,
  UsePipes,
  ValidationPipe,
  Get,
  Req,
} from '@nestjs/common';
import { RegisterDto } from '@backend/dto/auth/register.dto';
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
  async login(
    @Body() body: { email: string; password: string; token?: string },
  ) {
    const user: User | undefined = await this.authService.getUserByEmail(
      body.email,
    );
    if (!user || !user.passwordHash) {
      return { error: 'Invalid credentials' };
    }
    const valid = await this.authService.comparePassword(
      body.password,
      user.passwordHash,
    );
    if (!valid) {
      return { error: 'Invalid credentials' };
    }
    // If 2FA is enabled, require TOTP token
    if (user.twoFaSecret) {
      if (!body.token) {
        return { error: '2FA token required' };
      }
      // Decrypt secret
      const secret = this.authService.decryptSecret(user.twoFaSecret);
      const is2faValid = this.authService.verify2faToken(secret, body.token);
      if (!is2faValid) {
        return { error: 'Invalid 2FA token' };
      }
    }
    // Issue JWT token here
    const token = this.authService.generateJwt(user);
    return {
      email: user.email,
      id: user.id,
      token,
      message: 'Login successful',
    };
  }

  /**
   * Step 1: 2FA Setup - Generate TOTP secret and otpauth URL
   * POST /auth/2fa/setup { email }
   */
  @Post('2fa/setup')
  async setup2fa(@Body() body: { email: string }) {
    const user = await this.authService.getUserByEmail(body.email);
    if (!user) {
      return { error: 'User not found' };
    }
    // Generate secret and otpauthUrl
    const { secret, otpauthUrl } = this.authService.generate2faSecret(
      user.email,
    );
    // Do NOT save secret yet; only after verification
    return { secret, otpauthUrl };
  }

  /**
   * Step 1: 2FA Verification - Verify TOTP code and enable 2FA
   * POST /auth/2fa/verify { email, token, secret }
   */
  @Post('2fa/verify')
  async verify2fa(
    @Body() body: { email: string; token: string; secret: string },
  ) {
    const user = await this.authService.getUserByEmail(body.email);
    if (!user) {
      return { error: 'User not found' };
    }
    // Verify token
    const valid = this.authService.verify2faToken(body.secret, body.token);
    if (!valid) {
      return { error: 'Invalid 2FA token' };
    }
    // Encrypt secret before saving
    user.twoFaSecret = this.authService.encryptSecret(body.secret);
    // Use public saveUser method
    await this.authService.saveUser(user);
    return { message: '2FA enabled' };
  }

  /**
   * Step 1: 2FA Status - Check if 2FA is enabled for user
   * GET /auth/2fa/status?email=...
   */
  @Get('2fa/status')
  async twofaStatus(@Req() req: Request) {
    const email = req.query.email as string;
    if (!email) {
      return { error: 'Email required' };
    }
    const user = await this.authService.getUserByEmail(email);
    if (!user) {
      return { error: 'User not found' };
    }
    return { enabled: !!user.twoFaSecret };
  }
}
