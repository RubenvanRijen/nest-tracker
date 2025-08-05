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
import { JwtAuthGuard } from '@backend/guards/auth/jwt-auth.guard';
import { RegisterDto } from '@backend/dto/auth/register.dto';
import { LoginDto } from '@backend/dto/auth/login.dto';
import { TwoFactorAuthVerifyDto } from '@backend/dto/auth/twofa-verify.dto';
import { RefreshTokenDto } from '@backend/dto/auth/refresh-token.dto';
import { AuthService } from '@backend/services/auth/auth.service';
import { TwoFaService } from '@backend/services/auth/twofa.service';
import type { IAuthRequest } from '@backend/interfaces/auth/IAuthRequest';
import { Throttle } from '@nestjs/throttler';

/**
 * Rate limiting options for login attempts.
 * Allows 5 attempts per minute (60000ms).
 */
const loginThrottleOptions = {
  default: { limit: 5, ttl: 60000 },
};

/**
 * Rate limiting options for two-factor authentication attempts.
 * Allows 5 attempts per minute (60000ms).
 */
const twoFaThrottleOptions = {
  default: { limit: 5, ttl: 60000 },
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

  /**
   * Handles user login with email and password.
   * If 2FA is enabled, requires additional verification.
   * Otherwise, issues JWT and refresh tokens.
   */
  @Post('login')
  @Throttle(loginThrottleOptions)
  async login(@Body() body: LoginDto) {
    const { user, jwt, refreshToken } = await this.authService.loginUser(
      body.email,
      body.password,
    );

    if (user.twoFaSecret) {
      return {
        message: 'Two-factor authentication required',
        twoFaEnabled: true,
        email: user.email,
      };
    }

    return {
      email: user.email,
      id: user.id,
      token: jwt,
      refreshToken,
      message: 'Login successful',
      twoFaEnabled: false,
    };
  }

  /**
   * Handles two-factor authentication login.
   * Verifies the 2FA token and issues JWT and refresh tokens if valid.
   */
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

    // Update last used timestamp
    user.twoFaLastUsed = new Date();
    await this.authService.saveUser(user);

    // Generate tokens
    const jwt = this.authService.generateJwt(user);
    const refreshToken = await this.authService.generateRefreshToken(user);
    
    return {
      email: user.email,
      id: user.id,
      token: jwt,
      refreshToken,
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
  
  /**
   * Refreshes an access token using a valid refresh token.
   * Returns a new access token and refresh token pair.
   */
  @Post('refresh')
  @HttpCode(200)
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  async refreshToken(@Body() body: RefreshTokenDto) {
    try {
      // Get the user ID from the database by validating the refresh token
      // The refreshJwtToken method will handle validation and token comparison
      const { token, refreshToken } = await this.authService.refreshJwtToken(
        body.userId,
        body.refreshToken
      );
      
      return {
        token,
        refreshToken,
        message: 'Token refreshed successfully',
      };
    } catch (error) {
      if (error.status === 403) {
        throw error; // Pass through ForbiddenException
      }
      throw new UnauthorizedException('Invalid refresh token');
    }
  }
}
