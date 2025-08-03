import { Module } from '@nestjs/common';
import { AppController } from '@backend/app.controller';
import { AppService } from '@backend/app.service';
import { AuthModule } from '@backend/modules/auth/auth.module';
import { ApiKeyModule } from '@backend/modules/api-key.module';
import { TwoFaModule } from '@backend/modules/twofa.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import { dataSourceOptions } from '@backend/settings/database/data-source';

@Module({
  imports: [
    TypeOrmModule.forRoot(dataSourceOptions),
    AuthModule,
    ApiKeyModule,
    TwoFaModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
