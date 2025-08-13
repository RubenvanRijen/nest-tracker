import { Test, TestingModule } from '@nestjs/testing';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { DatabaseTestUtils } from './database-test-utils';
import { dataSourceOptions } from '@backend/settings/database/data-source';
import { User } from '@backend/entities/user/user.entity';
import { ApiKey } from '@backend/entities/auth/api-key.entity';

export class TestBase {
  protected module: TestingModule;
  protected userRepository: Repository<User>;
  protected apiKeyRepository: Repository<ApiKey>;

  /**
   * Setup test module with database and common dependencies
   */
  protected async createTestModule(
    providers: any[] = [],
  ): Promise<TestingModule> {
    // Initialize test database
    await DatabaseTestUtils.initializeTestDatabase();

    const module = await Test.createTestingModule({
      imports: [
        TypeOrmModule.forRoot(dataSourceOptions),
        TypeOrmModule.forFeature([User, ApiKey]),
      ],
      providers: [
        ...providers,
        {
          provide: JwtService,
          useValue: {
            sign: jest.fn().mockReturnValue('mock-jwt-token'),
            verify: jest.fn().mockReturnValue({ userId: 'test-user-id' }),
          },
        },
      ],
    }).compile();

    this.module = module;
    this.userRepository = module.get('UserRepository');
    this.apiKeyRepository = module.get('ApiKeyRepository');

    return module;
  }

  /**
   * Clean up after tests
   */
  protected async cleanup(): Promise<void> {
    if (this.module) {
      await this.module.close();
    }
    await DatabaseTestUtils.closeTestDatabase();
  }

  /**
   * Reset database to clean state
   */
  protected async resetDatabase(): Promise<void> {
    await DatabaseTestUtils.clearAllTables();
    await DatabaseTestUtils.seedTestDatabase();
  }

  /**
   * Create a test user with optional customizations
   */
  protected async createTestUser(overrides: Partial<User> = {}): Promise<User> {
    const userData = {
      email: `testuser-${Date.now()}@example.com`,
      passwordHash: await bcrypt.hash('TestPassword123!', 10),
      roles: ['user'],
      ...overrides,
    };

    const user = this.userRepository.create(userData);
    return await this.userRepository.save(user);
  }

  /**
   * Create a test API key for a user
   */
  protected async createTestApiKey(
    user: User,
    overrides: Partial<ApiKey> = {},
  ): Promise<ApiKey> {
    const apiKeyData = {
      keyHash: await bcrypt.hash(`test-api-key-${Date.now()}`, 10),
      user,
      active: true,
      scopes: ['read', 'write'],
      description: 'Test API Key',
      ...overrides,
    };

    const apiKey = this.apiKeyRepository.create(apiKeyData);
    return await this.apiKeyRepository.save(apiKey);
  }

  /**
   * Get seeded test users by email
   */
  protected async getSeededUser(email: string): Promise<User | null> {
    return await this.userRepository.findOne({ where: { email } });
  }

  /**
   * Mock authentication for tests
   */
  protected createMockAuthRequest(userId: string, roles: string[] = ['user']) {
    return {
      user: {
        userId,
        email: 'test@example.com',
        roles,
      },
    };
  }

  /**
   * Compare password with hash
   */
  protected async comparePassword(
    password: string,
    hash: string,
  ): Promise<boolean> {
    return await bcrypt.compare(password, hash);
  }

  /**
   * Wait for a specified amount of time (useful for async operations)
   */
  protected async wait(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
