import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { ApiKeyService } from '@backend/services/auth/api-key.service';
import { Request } from 'express';
import { IAuthRequest } from '@backend/interfaces/auth/IAuthRequest';

@Injectable()
export class ApiKeyAuthGuard implements CanActivate {
  constructor(private readonly apiKeyService: ApiKeyService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<IAuthRequest>();
    const apiKey = req.headers['x-api-key'] as string | undefined;
    if (!apiKey) {
      throw new UnauthorizedException('API key missing');
    }
    const user = await this.apiKeyService.validateApiKey(apiKey);
    if (!user) {
      throw new UnauthorizedException('Invalid API key');
    }
    req.user = user;
    return true;
  }
}
