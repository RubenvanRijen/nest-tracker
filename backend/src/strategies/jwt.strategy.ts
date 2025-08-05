/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { AuthService } from '@backend/services/auth/auth.service';

// Define the JWT payload interface
interface JwtPayload {
  sub: string;
  email: string;
  roles?: string[];
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly authService: AuthService) {
    if (!process.env.JWT_SECRET) {
      throw new Error('JWT_SECRET environment variable is not set');
    }
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_SECRET,
    });
  }

  async validate(payload: JwtPayload): Promise<any> {
    // Payload contains the data we included when generating the token
    // (sub: user.id, email: user.email, roles: user.roles)
    const user = await this.authService.getUserByEmail(payload.email);

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // Add roles from token to ensure authorization works correctly
    if (payload.roles && Array.isArray(payload.roles)) {
      user.roles = [...payload.roles];
    }

    return user;
  }
}
