import { Module, InternalServerErrorException } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { AuthService } from '@backend/services/auth/auth.service';
import { AuthController } from '@backend/controllers/auth/auth.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from '@backend/entities/user/user.entity';
import { ApiKey } from '@backend/entities/auth/api-key.entity';
import { TwoFaService } from '@backend/services/auth/twofa.service';
import { ApiKeyService } from '@backend/services/auth/api-key.service';
import { PasswordPolicyService } from '@backend/services/auth/password-policy.service';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';
import { JwtStrategy } from '@backend/strategies/jwt.strategy';

@Module({
  imports: [
    TypeOrmModule.forFeature([User, ApiKey]),
    PassportModule,
    JwtModule.registerAsync({
      useFactory: () => {
        const secret = process.env.JWT_SECRET;
        if (!secret) {
          throw new InternalServerErrorException(
            'JWT_SECRET must be set in environment',
          );
        }
        return {
          secret,
          signOptions: { expiresIn: '1h' },
        };
      },
    }),
    ThrottlerModule.forRoot([
      {
        ttl: 60000,
        limit: 10,
      },
    ]),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    TwoFaService,
    ApiKeyService,
    PasswordPolicyService,
    JwtStrategy,
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
  ],
  exports: [AuthService],
})
export class AuthModule {}
