import { Module } from '@nestjs/common';
import { Environment } from '../common/environment.enum';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { AuthService } from '@backend/auth/auth.service';
import { AuthController } from '@backend/auth/auth.controller';

@Module({
  imports: [
    PassportModule,
    JwtModule.register({
      secret: (() => {
        const secret = process.env.JWT_SECRET;
        const envValue: string = process.env.NODE_ENV ?? 'development';
        let env: Environment;
        switch (envValue) {
          case 'production':
            env = Environment.Production;
            break;
          case 'test':
            env = Environment.Test;
            break;
          default:
            env = Environment.Development;
        }
        if (!secret && env === Environment.Production) {
          throw new Error('JWT_SECRET must be set in production environment');
        }
        return secret || 'dev_secret_key'; // Use a secure default only for development/test
      })(),
      signOptions: { expiresIn: '1h' },
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService],
  exports: [AuthService],
})
export class AuthModule {}
