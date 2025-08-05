import {
    Controller,
    Post,
    Delete,
    Get,
    Param,
    Req,
    UseGuards,
    Body,
    Logger,
    UnauthorizedException,
} from '@nestjs/common';
import type {IAuthRequest} from '@backend/interfaces/auth/IAuthRequest';
import {ApiKeyService} from '@backend/services/auth/api-key.service';
import {JwtAuthGuard} from '@backend/guards/auth/jwt-auth.guard';
import {GenerateApiKeyDto, RotateApiKeyDto} from '@backend/dto/auth/api-key.dto';
import {
    ApiTags,
    ApiOperation,
    ApiBearerAuth,
    ApiBody,
    ApiOkResponse,
    ApiCreatedResponse,
    ApiUnauthorizedResponse,
    ApiParam,
} from '@nestjs/swagger';

@ApiTags('API Keys')
@ApiBearerAuth()
@Controller('api-keys')
@UseGuards(JwtAuthGuard)
export class ApiKeyController {
    private readonly logger = new Logger(ApiKeyController.name);

    constructor(private readonly apiKeyService: ApiKeyService) {
    }

    @Post('generate')
    @ApiOperation({ summary: 'Generate a new API key' })
    @ApiBody({ type: GenerateApiKeyDto })
    @ApiCreatedResponse({
        description: 'API key generated successfully',
        schema: {
            properties: {
                apiKey: { type: 'string', example: '123e4567-e89b-12d3-a456-426614174000' },
                rawKey: { type: 'string', example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0' }
            }
        }
    })
    @ApiUnauthorizedResponse({ description: 'Unauthorized - valid JWT required' })
    async generate(@Req() req: IAuthRequest, @Body() body: GenerateApiKeyDto) {
        const userId = req.user?.id;
        if (!userId) throw new UnauthorizedException('User not found in request');
        const {apiKey, rawKey} = await this.apiKeyService.generateApiKey(
            userId,
            body.scopes,
            body.description
        );
        this.logger.log(`API key generated for user: ${userId}`);
        return {apiKey: apiKey.id, rawKey};
    }

    @Post('rotate')
    @ApiOperation({ summary: 'Rotate an existing API key' })
    @ApiBody({ type: RotateApiKeyDto })
    @ApiCreatedResponse({
        description: 'API key rotated successfully',
        schema: {
            properties: {
                apiKey: { type: 'string', example: '123e4567-e89b-12d3-a456-426614174000' },
                rawKey: { type: 'string', example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0' }
            }
        }
    })
    @ApiUnauthorizedResponse({ description: 'Unauthorized - valid JWT required or API key not owned by user' })
    async rotate(@Req() req: IAuthRequest, @Body() body: RotateApiKeyDto) {
        const userId = req.user?.id;
        if (!userId) throw new UnauthorizedException('User not found in request');
        const {apiKey, rawKey} = await this.apiKeyService.rotateApiKey(
            userId,
            body.apiKeyId,
            body.scopes,
            body.description
        );
        this.logger.log(`API key rotated for user: ${userId}`);
        return {apiKey: apiKey.id, rawKey};
    }

    @Get()
    @ApiOperation({ summary: 'List all API keys for the current user' })
    @ApiOkResponse({
        description: 'List of API keys',
        schema: {
            type: 'array',
            items: {
                properties: {
                    id: { type: 'string', example: '123e4567-e89b-12d3-a456-426614174000' },
                    active: { type: 'boolean', example: true },
                    scopes: { type: 'array', items: { type: 'string' }, example: ['read', 'write'] },
                    description: { type: 'string', example: 'Integration with CRM system' },
                    createdAt: { type: 'string', format: 'date-time', example: '2023-01-01T00:00:00Z' }
                }
            }
        }
    })
    @ApiUnauthorizedResponse({ description: 'Unauthorized - valid JWT required' })
    async list(@Req() req: IAuthRequest) {
        const userId = req.user?.id;
        if (!userId) throw new Error('User not found in request');
        return this.apiKeyService.listUserApiKeys(userId);
    }

    @Delete(':id')
    @ApiOperation({ summary: 'Revoke an API key' })
    @ApiParam({ name: 'id', description: 'API key ID to revoke', example: '123e4567-e89b-12d3-a456-426614174000' })
    @ApiOkResponse({
        description: 'API key revoked successfully',
        schema: {
            properties: {
                success: { type: 'boolean', example: true }
            }
        }
    })
    @ApiUnauthorizedResponse({ description: 'Unauthorized - valid JWT required' })
    async revoke(@Param('id') id: string, @Req() req: IAuthRequest) {
        const userId = req.user?.id;
        if (!userId) throw new Error('User not found in request');
        await this.apiKeyService.revokeApiKey(id);
        this.logger.log(`API key ${id} revoked by user: ${userId}`);
        return {success: true};
    }
}
