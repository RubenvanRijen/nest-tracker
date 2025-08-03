import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ApiKeyController } from '@backend/controllers/api-key/api-key.controller';
import { ApiKeyService } from '@backend/services/api-key/api-key.service';
import { ApiKey } from '@backend/entities/api-key/api-key.entity';
import { User } from '@backend/entities/user/user.entity';
import { ApiKeyAuthGuard } from '@backend/guards/api-key-auth.guard';

@Module({
  imports: [TypeOrmModule.forFeature([ApiKey, User])],
  controllers: [ApiKeyController],
  providers: [ApiKeyService, ApiKeyAuthGuard],
  exports: [ApiKeyService],
})
export class ApiKeyModule {}
