import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ApiKeyController } from '@backend/controllers/auth/api-key.controller';
import { ApiKeyService } from '@backend/services/auth/api-key.service';
import { ApiKey } from '@backend/entities/auth/api-key.entity';
import { User } from '@backend/entities/user/user.entity';
import { ApiKeyAuthGuard } from '@backend/guards/auth/api-key-auth.guard';

@Module({
  imports: [TypeOrmModule.forFeature([ApiKey, User])],
  controllers: [ApiKeyController],
  providers: [ApiKeyService, ApiKeyAuthGuard],
  exports: [ApiKeyService],
})
export class ApiKeyModule {}
