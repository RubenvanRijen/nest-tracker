import {
    Injectable,
    CanActivate,
    ExecutionContext,
    UnauthorizedException,
    ForbiddenException,
} from '@nestjs/common';
import {ApiKeyService} from '@backend/services/auth/api-key.service';
import {IAuthRequest} from '@backend/interfaces/auth/IAuthRequest';
import {Reflector} from '@nestjs/core';

import {API_KEY_SCOPES} from '@backend/decorators/api-key-scopes.decorator';

@Injectable()
export class ApiKeyAuthGuard implements CanActivate {
    constructor(
        private readonly apiKeyService: ApiKeyService,
        private readonly reflector: Reflector
    ) {
    }

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const req = context.switchToHttp().getRequest<IAuthRequest>();
        const apiKey = req.headers['x-api-key'] as string | undefined;

        if (!apiKey) {
            throw new UnauthorizedException('API key missing');
        }

        const result = await this.apiKeyService.validateApiKey(apiKey);
        if (!result) {
            throw new UnauthorizedException('Invalid API key');
        }

        const {user, apiKey: keyEntity} = result;

        // Get required scopes from handler metadata
        const requiredScopes = this.reflector.getAllAndOverride<string[]>(API_KEY_SCOPES, [
            context.getHandler(),
            context.getClass(),
        ]) || [];

        // Check if the API key has the required scopes
        if (requiredScopes.length > 0) {
            const hasScopes = await this.apiKeyService.hasRequiredScopes(keyEntity, requiredScopes);
            if (!hasScopes) {
                throw new ForbiddenException('API key does not have the required scopes');
            }
        }

        // Store both user and API key in request
        req.user = user;
        req.apiKey = keyEntity;

        return true;
    }
}
