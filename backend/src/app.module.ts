import { Module } from '@nestjs/common';
import { AppController } from '@backend/app.controller';
import { AppService } from '@backend/app.service';
import { AuthModule } from '@backend/modules/auth/auth.module';
import { ApiKeyModule } from '@backend/modules/auth/api-key.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import { dataSourceOptions } from '@backend/settings/database/data-source';
import { ThrottlerModule } from '@nestjs/throttler';
import { ConfigModule } from '@nestjs/config';
import { validationSchema } from '@backend/config/env.validation';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      // Load .env.testing automatically in test, falling back to .env
      envFilePath: process.env.NODE_ENV === 'test' ? ['.env.testing', '.env'] : ['.env'],
      validationSchema,
      validationOptions: {
        abortEarly: true,
      },
    }),
    TypeOrmModule.forRoot(dataSourceOptions),
    ThrottlerModule.forRoot({
      throttlers: [
        {
          ttl: 60,
          limit: 5,
        },
      ],
    }),
    AuthModule,
    ApiKeyModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
