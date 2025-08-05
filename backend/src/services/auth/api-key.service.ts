import { Injectable, UnauthorizedException, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ApiKey } from '@backend/entities/auth/api-key.entity';
import { User } from '@backend/entities/user/user.entity';
import * as crypto from 'crypto';

@Injectable()
export class ApiKeyService {
  private readonly logger = new Logger(ApiKeyService.name);

  constructor(
    @InjectRepository(ApiKey)
    private readonly apiKeyRepository: Repository<ApiKey>,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  async generateApiKey(
    userId: string,
    scopes: string[] = ['default'],
    description?: string,
  ): Promise<{ apiKey: ApiKey; rawKey: string }> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      this.logger.warn(
        `API key generation attempt for non-existent user ID: ${userId}`,
      );
      throw new UnauthorizedException('User not found');
    }
    const rawKey = crypto.randomBytes(32).toString('hex');
    const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
    const apiKey = this.apiKeyRepository.create({
      keyHash,
      user,
      scopes,
      description,
    });
    await this.apiKeyRepository.save(apiKey);
    this.logger.log(
      `API key generated for user: ${userId}, key ID: ${apiKey.id}, scopes: ${scopes.join(',')}`,
    );
    return { apiKey, rawKey };
  }

  async validateApiKey(
    rawKey: string,
  ): Promise<{ user: User; apiKey: ApiKey } | null> {
    const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
    const apiKey = await this.apiKeyRepository.findOne({
      where: { keyHash, active: true },
      relations: ['user'],
    });

    if (!apiKey) {
      this.logger.warn('API key validation failed: invalid or inactive key');
      return null;
    }

    this.logger.log(
      `API key validated successfully for user: ${apiKey.user.id}, key ID: ${apiKey.id}`,
    );
    return { user: apiKey.user, apiKey };
  }

  async hasRequiredScopes(
    apiKey: ApiKey,
    requiredScopes: string[],
  ): Promise<boolean> {
    // If no scopes are required, allow access
    if (!requiredScopes || requiredScopes.length === 0) {
      return true;
    }

    // If the API key has no scopes, deny access
    if (!apiKey.scopes || apiKey.scopes.length === 0) {
      return false;
    }

    // Check if the API key has all required scopes
    return requiredScopes.every((scope) => apiKey.scopes.includes(scope));
  }

  async revokeApiKey(apiKeyId: string): Promise<void> {
    const result = await this.apiKeyRepository.update(apiKeyId, {
      active: false,
    });
    if (result.affected && result.affected > 0) {
      this.logger.log(`API key revoked: ${apiKeyId}`);
    } else {
      this.logger.warn(`API key revocation failed, key not found: ${apiKeyId}`);
    }
  }

  async listUserApiKeys(userId: string): Promise<ApiKey[]> {
    this.logger.log(`Listing API keys for user: ${userId}`);
    return this.apiKeyRepository.find({ where: { user: { id: userId } } });
  }

  async rotateApiKey(
    userId: string,
    apiKeyId: string,
    scopes?: string[],
    description?: string,
  ): Promise<{ apiKey: ApiKey; rawKey: string }> {
    // Find the existing API key and verify ownership
    const existingKey = await this.apiKeyRepository.findOne({
      where: { id: apiKeyId },
      relations: ['user'],
    });

    if (!existingKey) {
      this.logger.warn(`API key rotation failed: key not found: ${apiKeyId}`);
      throw new UnauthorizedException('API key not found');
    }

    if (existingKey.user.id !== userId) {
      this.logger.warn(
        `API key rotation failed: user ${userId} attempted to rotate key ${apiKeyId} owned by ${existingKey.user.id}`,
      );
      throw new UnauthorizedException('You do not own this API key');
    }

    // Revoke the existing key
    await this.revokeApiKey(apiKeyId);

    // Generate a new key with the same or updated scopes
    const newScopes = scopes || existingKey.scopes || ['default'];
    const newDescription = description || existingKey.description;

    this.logger.log(`Rotating API key ${apiKeyId} for user: ${userId}`);
    return this.generateApiKey(userId, newScopes, newDescription);
  }
}
