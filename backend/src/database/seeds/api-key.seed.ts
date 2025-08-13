import * as bcrypt from 'bcryptjs';
import { DataSource } from 'typeorm';
import { ApiKey } from '@backend/entities/auth/api-key.entity';
import { User } from '@backend/entities/user/user.entity';

export class ApiKeySeeder {
  public async run(dataSource: DataSource): Promise<void> {
    const apiKeyRepository = dataSource.getRepository(ApiKey);
    const userRepository = dataSource.getRepository(User);

    // Clear existing API keys
    await apiKeyRepository.delete({});

    // Get test users
    const apiUser = await userRepository.findOne({
      where: { email: 'apiuser@example.com' },
    });
    const adminUser = await userRepository.findOne({
      where: { email: 'admin@example.com' },
    });

    if (!apiUser || !adminUser) {
      throw new Error('Test users not found. Run user seeder first.');
    }

    // Test API keys
    const testApiKeys = [
      {
        id: '660e8400-e29b-41d4-a716-446655440000',
        keyHash: await bcrypt.hash('test-api-key-123', 10),
        user: apiUser,
        active: true,
        scopes: ['read', 'write'],
        description: 'Test API Key for automated testing',
      },
      {
        id: '660e8400-e29b-41d4-a716-446655440001',
        keyHash: await bcrypt.hash('admin-api-key-456', 10),
        user: adminUser,
        active: true,
        scopes: ['read', 'write', 'admin'],
        description: 'Admin API Key with full permissions',
      },
      {
        id: '660e8400-e29b-41d4-a716-446655440002',
        keyHash: await bcrypt.hash('readonly-api-key-789', 10),
        user: apiUser,
        active: true,
        scopes: ['read'],
        description: 'Read-only API Key for testing',
      },
      {
        id: '660e8400-e29b-41d4-a716-446655440003',
        keyHash: await bcrypt.hash('inactive-api-key-999', 10),
        user: apiUser,
        active: false,
        scopes: ['read'],
        description: 'Inactive API Key for testing',
      },
    ];

    // Insert test API keys
    for (const apiKeyData of testApiKeys) {
      const apiKey = apiKeyRepository.create(apiKeyData);
      await apiKeyRepository.save(apiKey);
    }

    console.log('✅ API Key seeding completed');
  }
}
