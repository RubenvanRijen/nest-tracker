import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { TwoFaController } from '@backend/controllers/twofa/twofa.controller';
import { TwoFaService } from '@backend/services/twofa/twofa.service';
import { User } from '@backend/entities/user/user.entity';

@Module({
  imports: [TypeOrmModule.forFeature([User])],
  controllers: [TwoFaController],
  providers: [TwoFaService],
  exports: [TwoFaService],
})
export class TwoFaModule {}
