import { User } from './user.entity';
import { ApiKey } from '@backend/entities/auth/api-key.entity';
import * as bcrypt from 'bcryptjs';

describe('User Entity', () => {
  let user: User;

  beforeEach(() => {
    user = new User();
  });

  describe('Entity Properties', () => {
    it('should create a user with default values', () => {
      expect(user).toBeDefined();
      expect(user.id).toBeUndefined();
      expect(user.email).toBeUndefined();
      expect(user.passwordHash).toBeUndefined();
      expect(user.roles).toBeUndefined();
    });

    it('should allow setting basic user properties', () => {
      user.id = '550e8400-e29b-41d4-a716-446655440000';
      user.email = 'test@example.com';
      user.passwordHash = 'hashed-password';
      user.roles = ['user'];

      expect(user.id).toBe('550e8400-e29b-41d4-a716-446655440000');
      expect(user.email).toBe('test@example.com');
      expect(user.passwordHash).toBe('hashed-password');
      expect(user.roles).toEqual(['user']);
    });

    it('should handle optional authentication fields', () => {
      user.twoFaSecret = 'encrypted-secret';
      user.pendingTwoFaSecret = 'pending-secret';
      user.twoFaLastUsed = new Date('2024-01-01');
      user.twoFaBackupCodes = ['code1', 'code2'];
      user.passkeyId = 'passkey-123';

      expect(user.twoFaSecret).toBe('encrypted-secret');
      expect(user.pendingTwoFaSecret).toBe('pending-secret');
      expect(user.twoFaLastUsed).toEqual(new Date('2024-01-01'));
      expect(user.twoFaBackupCodes).toEqual(['code1', 'code2']);
      expect(user.passkeyId).toBe('passkey-123');
    });

    it('should handle JWT refresh token fields', () => {
      const expirationDate = new Date('2024-12-31');
      user.refreshTokenHash = 'hashed-refresh-token';
      user.refreshTokenExpiresAt = expirationDate;

      expect(user.refreshTokenHash).toBe('hashed-refresh-token');
      expect(user.refreshTokenExpiresAt).toEqual(expirationDate);
    });

    it('should handle role arrays correctly', () => {
      user.roles = ['user', 'admin'];
      expect(user.roles).toEqual(['user', 'admin']);
      expect(user.roles).toHaveLength(2);

      user.roles = [];
      expect(user.roles).toEqual([]);
      expect(user.roles).toHaveLength(0);
    });
  });

  describe('Entity Relationships', () => {
    it('should support API keys relationship', () => {
      const apiKey1 = new ApiKey();
      apiKey1.id = '660e8400-e29b-41d4-a716-446655440000';
      apiKey1.keyHash = 'key-hash-1';

      const apiKey2 = new ApiKey();
      apiKey2.id = '660e8400-e29b-41d4-a716-446655440001';
      apiKey2.keyHash = 'key-hash-2';

      user.apiKeys = [apiKey1, apiKey2];

      expect(user.apiKeys).toHaveLength(2);
      expect(user.apiKeys[0]).toBe(apiKey1);
      expect(user.apiKeys[1]).toBe(apiKey2);
    });

    it('should handle empty API keys array', () => {
      user.apiKeys = [];
      expect(user.apiKeys).toEqual([]);
      expect(user.apiKeys).toHaveLength(0);
    });

    it('should handle undefined API keys', () => {
      expect(user.apiKeys).toBeUndefined();
    });
  });

  describe('Security Fields', () => {
    it('should handle password hash properly', async () => {
      const plainPassword = 'TestPassword123!';
      const hashedPassword = await bcrypt.hash(plainPassword, 10);
      user.passwordHash = hashedPassword;

      expect(user.passwordHash).toBeDefined();
      expect(user.passwordHash).not.toBe(plainPassword);
      expect(await bcrypt.compare(plainPassword, user.passwordHash)).toBe(true);
      expect(await bcrypt.compare('WrongPassword', user.passwordHash)).toBe(
        false,
      );
    });

    it('should handle API key hash', async () => {
      const plainApiKey = 'api-key-123';
      const hashedApiKey = await bcrypt.hash(plainApiKey, 10);
      user.apiKeyHash = hashedApiKey;

      expect(user.apiKeyHash).toBeDefined();
      expect(user.apiKeyHash).not.toBe(plainApiKey);
      expect(await bcrypt.compare(plainApiKey, user.apiKeyHash)).toBe(true);
    });

    it('should handle 2FA backup codes as hashed values', async () => {
      const backupCodes = ['BACKUP001', 'BACKUP002'];
      const hashedCodes = await Promise.all(
        backupCodes.map((code) => bcrypt.hash(code, 10)),
      );
      user.twoFaBackupCodes = hashedCodes;

      expect(user.twoFaBackupCodes).toHaveLength(2);
      expect(await bcrypt.compare('BACKUP001', user.twoFaBackupCodes[0])).toBe(
        true,
      );
      expect(await bcrypt.compare('BACKUP002', user.twoFaBackupCodes[1])).toBe(
        true,
      );
      expect(await bcrypt.compare('WRONG_CODE', user.twoFaBackupCodes[0])).toBe(
        false,
      );
    });
  });

  describe('Data Validation', () => {
    it('should handle email format', () => {
      const validEmails = [
        'test@example.com',
        'user.name@domain.co.uk',
        'test+label@example.org',
      ];

      validEmails.forEach((email) => {
        user.email = email;
        expect(user.email).toBe(email);
      });
    });

    it('should handle UUID format for ID', () => {
      const validUuid = '550e8400-e29b-41d4-a716-446655440000';
      user.id = validUuid;
      expect(user.id).toBe(validUuid);
      expect(user.id).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
      );
    });

    it('should handle date objects for timestamp fields', () => {
      const testDate = new Date('2024-01-01T10:00:00Z');
      user.twoFaLastUsed = testDate;
      user.refreshTokenExpiresAt = testDate;

      expect(user.twoFaLastUsed).toBeInstanceOf(Date);
      expect(user.refreshTokenExpiresAt).toBeInstanceOf(Date);
      expect(user.twoFaLastUsed.getTime()).toBe(testDate.getTime());
    });
  });
});
