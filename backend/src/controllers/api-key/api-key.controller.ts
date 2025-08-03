import {
  Controller,
  Post,
  Delete,
  Get,
  Param,
  Req,
  UseGuards,
} from '@nestjs/common';
import type { IAuthRequest } from '@backend/interfaces/auth/IAuthRequest';
import { ApiKeyService } from '@backend/services/api-key/api-key.service';
import { JwtAuthGuard } from '@backend/guards/jwt-auth.guard';

@Controller('api-keys')
@UseGuards(JwtAuthGuard)
export class ApiKeyController {
  constructor(private readonly apiKeyService: ApiKeyService) {}

  @Post('generate')
  async generate(@Req() req: IAuthRequest) {
    const userId = req.user?.id;
    if (!userId) throw new Error('User not found in request');
    const { apiKey, rawKey } = await this.apiKeyService.generateApiKey(userId);
    return { apiKey: apiKey.id, rawKey };
  }

  @Get()
  async list(@Req() req: IAuthRequest) {
    const userId = req.user?.id;
    if (!userId) throw new Error('User not found in request');
    return this.apiKeyService.listUserApiKeys(userId);
  }

  @Delete(':id')
  async revoke(@Param('id') id: string) {
    await this.apiKeyService.revokeApiKey(id);
    return { success: true };
  }
}
