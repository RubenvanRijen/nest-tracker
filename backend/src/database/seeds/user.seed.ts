import * as bcrypt from 'bcryptjs';
import { DataSource } from 'typeorm';
import { User } from '@backend/entities/user/user.entity';

export class UserSeeder {
  public async run(dataSource: DataSource): Promise<void> {
    const userRepository = dataSource.getRepository(User);

    // Clear existing data
    await userRepository.delete({});

    // Test users with hashed passwords
    const testUsers = [
      {
        id: '550e8400-e29b-41d4-a716-446655440000',
        email: 'testuser@example.com',
        passwordHash: await bcrypt.hash('TestPassword123!', 10),
        roles: ['user'],
      },
      {
        id: '550e8400-e29b-41d4-a716-446655440001',
        email: 'admin@example.com',
        passwordHash: await bcrypt.hash('AdminPassword123!', 10),
        roles: ['admin', 'user'],
        twoFaSecret: 'encrypted-test-secret',
        twoFaBackupCodes: [
          await bcrypt.hash('BACKUP001', 10),
          await bcrypt.hash('BACKUP002', 10),
        ],
      },
      {
        id: '550e8400-e29b-41d4-a716-446655440002',
        email: 'apiuser@example.com',
        passwordHash: await bcrypt.hash('ApiUserPassword123!', 10),
        roles: ['user'],
        apiKeyHash: await bcrypt.hash('test-api-key-123', 10),
      },
    ];

    // Insert test users
    for (const userData of testUsers) {
      const user = userRepository.create(userData);
      await userRepository.save(user);
    }

    console.log('✅ User seeding completed');
  }
}
