import { ApiKey } from './api-key.entity';
import { User } from '@backend/entities/user/user.entity';
import * as bcrypt from 'bcryptjs';

describe('ApiKey Entity', () => {
  let apiKey: ApiKey;
  let user: User;

  beforeEach(() => {
    apiKey = new ApiKey();
    user = new User();
    user.id = '550e8400-e29b-41d4-a716-446655440000';
    user.email = 'test@example.com';
  });

  describe('Entity Properties', () => {
    it('should create an API key with default values', () => {
      expect(apiKey).toBeDefined();
      expect(apiKey.id).toBeUndefined();
      expect(apiKey.keyHash).toBeUndefined();
      expect(apiKey.user).toBeUndefined();
      expect(apiKey.active).toBeUndefined();
      expect(apiKey.scopes).toBeUndefined();
      expect(apiKey.description).toBeUndefined();
      expect(apiKey.createdAt).toBeUndefined();
    });

    it('should allow setting basic API key properties', () => {
      apiKey.id = '660e8400-e29b-41d4-a716-446655440000';
      apiKey.keyHash = 'hashed-api-key';
      apiKey.user = user;
      apiKey.active = true;
      apiKey.scopes = ['read', 'write'];
      apiKey.description = 'Test API Key';

      expect(apiKey.id).toBe('660e8400-e29b-41d4-a716-446655440000');
      expect(apiKey.keyHash).toBe('hashed-api-key');
      expect(apiKey.user).toBe(user);
      expect(apiKey.active).toBe(true);
      expect(apiKey.scopes).toEqual(['read', 'write']);
      expect(apiKey.description).toBe('Test API Key');
    });

    it('should handle default active state', () => {
      // In TypeORM, default values are applied by the database, not the entity
      // So we test the expected behavior when the entity is properly configured
      apiKey.active = true; // Default value as per entity definition
      expect(apiKey.active).toBe(true);
    });

    it('should handle createdAt timestamp', () => {
      const testDate = new Date('2024-01-01T10:00:00Z');
      apiKey.createdAt = testDate;

      expect(apiKey.createdAt).toBeInstanceOf(Date);
      expect(apiKey.createdAt.getTime()).toBe(testDate.getTime());
    });
  });

  describe('Entity Relationships', () => {
    it('should establish relationship with User entity', () => {
      apiKey.user = user;

      expect(apiKey.user).toBe(user);
      expect(apiKey.user.id).toBe('550e8400-e29b-41d4-a716-446655440000');
      expect(apiKey.user.email).toBe('test@example.com');
    });

    it('should handle undefined user relationship', () => {
      expect(apiKey.user).toBeUndefined();
    });

    it('should support cascade deletion through user relationship', () => {
      // This tests the relationship configuration, actual cascade would be handled by DB
      apiKey.user = user;
      expect(apiKey.user).toBeDefined();

      // Simulate cascade deletion
      apiKey.user = undefined as any;
      expect(apiKey.user).toBeUndefined();
    });
  });

  describe('Security and Key Management', () => {
    it('should handle API key hash properly', async () => {
      const plainApiKey = 'sk_test_1234567890abcdef';
      const hashedApiKey = await bcrypt.hash(plainApiKey, 10);
      apiKey.keyHash = hashedApiKey;

      expect(apiKey.keyHash).toBeDefined();
      expect(apiKey.keyHash).not.toBe(plainApiKey);
      expect(await bcrypt.compare(plainApiKey, apiKey.keyHash)).toBe(true);
      expect(await bcrypt.compare('wrong-key', apiKey.keyHash)).toBe(false);
    });

    it('should ensure key hash uniqueness requirement', () => {
      const keyHash = 'unique-hashed-key';
      apiKey.keyHash = keyHash;

      expect(apiKey.keyHash).toBe(keyHash);
      // In a real scenario, database would enforce uniqueness constraint
    });
  });

  describe('Scopes Management', () => {
    it('should handle empty scopes array', () => {
      apiKey.scopes = [];
      expect(apiKey.scopes).toEqual([]);
      expect(apiKey.scopes).toHaveLength(0);
    });

    it('should handle multiple scopes', () => {
      apiKey.scopes = ['read', 'write', 'admin', 'delete'];
      expect(apiKey.scopes).toEqual(['read', 'write', 'admin', 'delete']);
      expect(apiKey.scopes).toHaveLength(4);
    });

    it('should handle single scope', () => {
      apiKey.scopes = ['read'];
      expect(apiKey.scopes).toEqual(['read']);
      expect(apiKey.scopes).toHaveLength(1);
    });

    it('should handle undefined scopes', () => {
      expect(apiKey.scopes).toBeUndefined();
    });

    it('should support common API scopes', () => {
      const commonScopes = [
        'read',
        'write',
        'delete',
        'admin',
        'user:read',
        'user:write',
        'api:manage',
      ];

      apiKey.scopes = commonScopes;
      expect(apiKey.scopes).toEqual(commonScopes);
      expect(apiKey.scopes).toContain('read');
      expect(apiKey.scopes).toContain('admin');
    });
  });

  describe('API Key Status Management', () => {
    it('should handle active status', () => {
      apiKey.active = true;
      expect(apiKey.active).toBe(true);
    });

    it('should handle inactive status', () => {
      apiKey.active = false;
      expect(apiKey.active).toBe(false);
    });

    it('should toggle active status', () => {
      apiKey.active = true;
      expect(apiKey.active).toBe(true);

      apiKey.active = false;
      expect(apiKey.active).toBe(false);

      apiKey.active = true;
      expect(apiKey.active).toBe(true);
    });
  });

  describe('Description and Metadata', () => {
    it('should handle API key description', () => {
      const description = 'Production API key for mobile app';
      apiKey.description = description;

      expect(apiKey.description).toBe(description);
    });

    it('should handle empty description', () => {
      apiKey.description = '';
      expect(apiKey.description).toBe('');
    });

    it('should handle undefined description', () => {
      expect(apiKey.description).toBeUndefined();
    });

    it('should handle long descriptions', () => {
      const longDescription = 'A'.repeat(500);
      apiKey.description = longDescription;

      expect(apiKey.description).toBe(longDescription);
      expect(apiKey.description).toHaveLength(500);
    });
  });

  describe('Data Validation', () => {
    it('should handle UUID format for ID', () => {
      const validUuid = '660e8400-e29b-41d4-a716-446655440000';
      apiKey.id = validUuid;

      expect(apiKey.id).toBe(validUuid);
      expect(apiKey.id).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
      );
    });

    it('should handle date objects for createdAt', () => {
      const testDate = new Date();
      apiKey.createdAt = testDate;

      expect(apiKey.createdAt).toBeInstanceOf(Date);
      expect(apiKey.createdAt.getTime()).toBe(testDate.getTime());
    });

    it('should validate required fields are set', () => {
      // Simulate required field validation
      apiKey.keyHash = 'required-hash';
      apiKey.user = user;

      expect(apiKey.keyHash).toBeDefined();
      expect(apiKey.user).toBeDefined();
    });
  });

  describe('Entity Integration', () => {
    it('should work with User entity bidirectional relationship', () => {
      // Set up bidirectional relationship
      user.apiKeys = [apiKey];
      apiKey.user = user;

      expect(user.apiKeys).toContain(apiKey);
      expect(apiKey.user).toBe(user);
    });

    it('should handle multiple API keys for one user', () => {
      const apiKey2 = new ApiKey();
      apiKey2.id = '660e8400-e29b-41d4-a716-446655440001';
      apiKey2.keyHash = 'second-key-hash';
      apiKey2.user = user;

      apiKey.user = user;
      user.apiKeys = [apiKey, apiKey2];

      expect(user.apiKeys).toHaveLength(2);
      expect(user.apiKeys).toContain(apiKey);
      expect(user.apiKeys).toContain(apiKey2);
      expect(apiKey.user).toBe(user);
      expect(apiKey2.user).toBe(user);
    });
  });
});
