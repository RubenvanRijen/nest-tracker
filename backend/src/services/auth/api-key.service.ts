import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ApiKey } from '@backend/entities/auth/api-key.entity';
import { User } from '@backend/entities/user/user.entity';
import * as crypto from 'crypto';

@Injectable()
export class ApiKeyService {
  constructor(
    @InjectRepository(ApiKey)
    private readonly apiKeyRepository: Repository<ApiKey>,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  async generateApiKey(
    userId: string,
  ): Promise<{ apiKey: ApiKey; rawKey: string }> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) throw new UnauthorizedException('User not found');
    const rawKey = crypto.randomBytes(32).toString('hex');
    const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
    const apiKey = this.apiKeyRepository.create({ keyHash, user });
    await this.apiKeyRepository.save(apiKey);
    return { apiKey, rawKey };
  }

  async validateApiKey(rawKey: string): Promise<User | null> {
    const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
    const apiKey = await this.apiKeyRepository.findOne({
      where: { keyHash, active: true },
      relations: ['user'],
    });
    return apiKey?.user ?? null;
  }

  async revokeApiKey(apiKeyId: string): Promise<void> {
    await this.apiKeyRepository.update(apiKeyId, { active: false });
  }

  async listUserApiKeys(userId: string): Promise<ApiKey[]> {
    return this.apiKeyRepository.find({ where: { user: { id: userId } } });
  }
}
