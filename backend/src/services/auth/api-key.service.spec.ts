import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { UnauthorizedException } from '@nestjs/common';
import * as crypto from 'crypto';
import { ApiKeyService } from './api-key.service';
import { ApiKey } from '@backend/entities/auth/api-key.entity';
import { User } from '@backend/entities/user/user.entity';

describe('ApiKeyService', () => {
  let service: ApiKeyService;
  let apiKeyRepository: jest.Mocked<Repository<ApiKey>>;
  let userRepository: jest.Mocked<Repository<User>>;

  const mockUser: User = {
    id: '550e8400-e29b-41d4-a716-446655440000',
    email: 'test@example.com',
    passwordHash: '$2b$10$hashedpassword',
    roles: ['user'],
    refreshTokenHash: null,
    refreshTokenExpiresAt: null,
    twoFaSecret: undefined,
    pendingTwoFaSecret: undefined,
    twoFaLastUsed: undefined,
    twoFaBackupCodes: undefined,
    passkeyId: undefined,
    apiKeyHash: undefined,
    apiKeys: undefined,
  };

  const mockApiKey: ApiKey = {
    id: '660e8400-e29b-41d4-a716-446655440000',
    keyHash: 'hashed-api-key',
    user: mockUser,
    active: true,
    scopes: ['read', 'write'],
    description: 'Test API Key',
    createdAt: new Date('2024-01-01T00:00:00Z'),
  };

  beforeEach(async () => {
    const mockApiKeyRepository = {
      create: jest.fn(),
      save: jest.fn(),
      findOne: jest.fn(),
      find: jest.fn(),
      update: jest.fn(),
    };

    const mockUserRepository = {
      findOne: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ApiKeyService,
        {
          provide: getRepositoryToken(ApiKey),
          useValue: mockApiKeyRepository,
        },
        {
          provide: getRepositoryToken(User),
          useValue: mockUserRepository,
        },
      ],
    }).compile();

    service = module.get<ApiKeyService>(ApiKeyService);
    apiKeyRepository = module.get(getRepositoryToken(ApiKey));
    userRepository = module.get(getRepositoryToken(User));
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('generateApiKey', () => {
    it('should generate a new API key for a user', async () => {
      const rawKey = 'raw-api-key-123';
      const keyHash = 'hashed-key-123';

      userRepository.findOne.mockResolvedValue(mockUser);
      apiKeyRepository.create.mockReturnValue(mockApiKey);
      apiKeyRepository.save.mockResolvedValue(mockApiKey);

      // Mock crypto functions
      jest.spyOn(crypto, 'randomBytes').mockReturnValue(Buffer.from(rawKey));
      jest
        .spyOn(crypto, 'createHash')
        .mockReturnValue({
          update: jest
            .fn()
            .mockReturnValue({ digest: jest.fn().mockReturnValue(keyHash) }),
        } as any);

      const result = await service.generateApiKey(
        mockUser.id,
        ['read', 'write'],
        'Test API Key',
      );

      expect(userRepository.findOne).toHaveBeenCalledWith({
        where: { id: mockUser.id },
      });
      expect(apiKeyRepository.create).toHaveBeenCalledWith({
        keyHash,
        user: mockUser,
        scopes: ['read', 'write'],
        description: 'Test API Key',
      });
      expect(apiKeyRepository.save).toHaveBeenCalledWith(mockApiKey);
      expect(result).toEqual({ apiKey: mockApiKey, rawKey });
    });

    it('should generate API key with default scopes when none provided', async () => {
      const rawKey = 'raw-api-key-123';
      const keyHash = 'hashed-key-123';

      userRepository.findOne.mockResolvedValue(mockUser);
      apiKeyRepository.create.mockReturnValue(mockApiKey);
      apiKeyRepository.save.mockResolvedValue(mockApiKey);

      jest.spyOn(crypto, 'randomBytes').mockReturnValue(Buffer.from(rawKey));
      jest
        .spyOn(crypto, 'createHash')
        .mockReturnValue({
          update: jest
            .fn()
            .mockReturnValue({ digest: jest.fn().mockReturnValue(keyHash) }),
        } as any);

      await service.generateApiKey(mockUser.id);

      expect(apiKeyRepository.create).toHaveBeenCalledWith({
        keyHash,
        user: mockUser,
        scopes: ['default'],
        description: undefined,
      });
    });

    it('should throw UnauthorizedException for non-existent user', async () => {
      userRepository.findOne.mockResolvedValue(null);

      await expect(
        service.generateApiKey('non-existent-user-id', ['read']),
      ).rejects.toThrow(UnauthorizedException);

      expect(userRepository.findOne).toHaveBeenCalledWith({
        where: { id: 'non-existent-user-id' },
      });
    });
  });

  describe('validateApiKey', () => {
    it('should validate a valid API key', async () => {
      const rawKey = 'raw-api-key-123';
      const keyHash = 'hashed-key-123';

      jest
        .spyOn(crypto, 'createHash')
        .mockReturnValue({
          update: jest
            .fn()
            .mockReturnValue({ digest: jest.fn().mockReturnValue(keyHash) }),
        } as any);
      apiKeyRepository.findOne.mockResolvedValue(mockApiKey);

      const result = await service.validateApiKey(rawKey);

      expect(apiKeyRepository.findOne).toHaveBeenCalledWith({
        where: { keyHash, active: true },
        relations: ['user'],
      });
      expect(result).toEqual({ user: mockUser, apiKey: mockApiKey });
    });

    it('should return null for invalid API key', async () => {
      const rawKey = 'invalid-api-key';
      const keyHash = 'invalid-hash';

      jest
        .spyOn(crypto, 'createHash')
        .mockReturnValue({
          update: jest
            .fn()
            .mockReturnValue({ digest: jest.fn().mockReturnValue(keyHash) }),
        } as any);
      apiKeyRepository.findOne.mockResolvedValue(null);

      const result = await service.validateApiKey(rawKey);

      expect(result).toBeNull();
    });

    it('should return null for inactive API key', async () => {
      const rawKey = 'inactive-api-key';
      const keyHash = 'inactive-hash';
      const inactiveApiKey = { ...mockApiKey, active: false };

      jest
        .spyOn(crypto, 'createHash')
        .mockReturnValue({
          update: jest
            .fn()
            .mockReturnValue({ digest: jest.fn().mockReturnValue(keyHash) }),
        } as any);
      apiKeyRepository.findOne.mockResolvedValue(null); // Inactive keys are filtered out by the query

      const result = await service.validateApiKey(rawKey);

      expect(result).toBeNull();
    });
  });

  describe('hasRequiredScopes', () => {
    it('should return true when API key has all required scopes', () => {
      const apiKey = { ...mockApiKey, scopes: ['read', 'write', 'admin'] };
      const requiredScopes = ['read', 'write'];

      const result = service.hasRequiredScopes(apiKey, requiredScopes);

      expect(result).toBe(true);
    });

    it('should return false when API key is missing required scopes', () => {
      const apiKey = { ...mockApiKey, scopes: ['read'] };
      const requiredScopes = ['read', 'write', 'admin'];

      const result = service.hasRequiredScopes(apiKey, requiredScopes);

      expect(result).toBe(false);
    });

    it('should return true when no scopes are required', () => {
      const apiKey = { ...mockApiKey, scopes: ['read'] };
      const requiredScopes: string[] = [];

      const result = service.hasRequiredScopes(apiKey, requiredScopes);

      expect(result).toBe(true);
    });

    it('should return true when required scopes are null or undefined', () => {
      const apiKey = { ...mockApiKey, scopes: ['read'] };

      expect(service.hasRequiredScopes(apiKey, null as any)).toBe(true);
      expect(service.hasRequiredScopes(apiKey, undefined as any)).toBe(true);
    });

    it('should return false when API key has no scopes but scopes are required', () => {
      const apiKey = { ...mockApiKey, scopes: [] };
      const requiredScopes = ['read'];

      const result = service.hasRequiredScopes(apiKey, requiredScopes);

      expect(result).toBe(false);
    });

    it('should return false when API key scopes are null/undefined but scopes are required', () => {
      const apiKey = { ...mockApiKey, scopes: null as any };
      const requiredScopes = ['read'];

      const result = service.hasRequiredScopes(apiKey, requiredScopes);

      expect(result).toBe(false);
    });
  });

  describe('revokeApiKey', () => {
    it('should revoke an API key successfully', async () => {
      const apiKeyId = '660e8400-e29b-41d4-a716-446655440000';
      apiKeyRepository.update.mockResolvedValue({ affected: 1 } as any);

      await service.revokeApiKey(apiKeyId);

      expect(apiKeyRepository.update).toHaveBeenCalledWith(apiKeyId, {
        active: false,
      });
    });

    it('should handle case when API key to revoke is not found', async () => {
      const apiKeyId = 'non-existent-key-id';
      apiKeyRepository.update.mockResolvedValue({ affected: 0 } as any);

      await service.revokeApiKey(apiKeyId);

      expect(apiKeyRepository.update).toHaveBeenCalledWith(apiKeyId, {
        active: false,
      });
      // Should not throw error, just log warning
    });
  });

  describe('listUserApiKeys', () => {
    it('should list all API keys for a user', async () => {
      const userApiKeys = [mockApiKey, { ...mockApiKey, id: 'another-key-id' }];
      apiKeyRepository.find.mockResolvedValue(userApiKeys);

      const result = await service.listUserApiKeys(mockUser.id);

      expect(apiKeyRepository.find).toHaveBeenCalledWith({
        where: { user: { id: mockUser.id } },
      });
      expect(result).toEqual(userApiKeys);
    });

    it('should return empty array when user has no API keys', async () => {
      apiKeyRepository.find.mockResolvedValue([]);

      const result = await service.listUserApiKeys(mockUser.id);

      expect(result).toEqual([]);
    });
  });

  describe('rotateApiKey', () => {
    it('should rotate an existing API key successfully', async () => {
      const existingKeyId = '660e8400-e29b-41d4-a716-446655440000';
      const newRawKey = 'new-raw-key-123';
      const newKeyHash = 'new-hashed-key-123';
      const newApiKey = {
        ...mockApiKey,
        id: 'new-key-id',
        keyHash: newKeyHash,
      };

      // Mock finding existing key
      apiKeyRepository.findOne.mockResolvedValueOnce(mockApiKey);
      // Mock update for revocation
      apiKeyRepository.update.mockResolvedValue({ affected: 1 } as any);
      // Mock user lookup for new key generation
      userRepository.findOne.mockResolvedValue(mockUser);
      // Mock new key creation
      apiKeyRepository.create.mockReturnValue(newApiKey);
      apiKeyRepository.save.mockResolvedValue(newApiKey);

      // Mock crypto functions
      jest.spyOn(crypto, 'randomBytes').mockReturnValue(Buffer.from(newRawKey));
      jest
        .spyOn(crypto, 'createHash')
        .mockReturnValue({
          update: jest
            .fn()
            .mockReturnValue({ digest: jest.fn().mockReturnValue(newKeyHash) }),
        } as any);

      const result = await service.rotateApiKey(
        mockUser.id,
        existingKeyId,
        ['read', 'write'],
        'Rotated API Key',
      );

      expect(apiKeyRepository.findOne).toHaveBeenCalledWith({
        where: { id: existingKeyId },
        relations: ['user'],
      });
      expect(apiKeyRepository.update).toHaveBeenCalledWith(existingKeyId, {
        active: false,
      });
      expect(result).toEqual({ apiKey: newApiKey, rawKey: newRawKey });
    });

    it('should rotate API key with existing scopes when none provided', async () => {
      const existingKeyId = '660e8400-e29b-41d4-a716-446655440000';
      const existingKey = { ...mockApiKey, scopes: ['existing', 'scopes'] };

      apiKeyRepository.findOne.mockResolvedValueOnce(existingKey);
      apiKeyRepository.update.mockResolvedValue({ affected: 1 } as any);
      userRepository.findOne.mockResolvedValue(mockUser);
      apiKeyRepository.create.mockReturnValue(mockApiKey);
      apiKeyRepository.save.mockResolvedValue(mockApiKey);

      jest.spyOn(crypto, 'randomBytes').mockReturnValue(Buffer.from('new-key'));
      jest
        .spyOn(crypto, 'createHash')
        .mockReturnValue({
          update: jest
            .fn()
            .mockReturnValue({ digest: jest.fn().mockReturnValue('new-hash') }),
        } as any);

      await service.rotateApiKey(mockUser.id, existingKeyId);

      expect(apiKeyRepository.create).toHaveBeenCalledWith(
        expect.objectContaining({
          scopes: ['existing', 'scopes'],
        }),
      );
    });

    it('should throw UnauthorizedException for non-existent API key', async () => {
      const nonExistentKeyId = 'non-existent-key-id';
      apiKeyRepository.findOne.mockResolvedValue(null);

      await expect(
        service.rotateApiKey(mockUser.id, nonExistentKeyId),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException when user does not own the API key', async () => {
      const existingKeyId = '660e8400-e29b-41d4-a716-446655440000';
      const differentUser = { ...mockUser, id: 'different-user-id' };
      const keyOwnedByDifferentUser = { ...mockApiKey, user: differentUser };

      apiKeyRepository.findOne.mockResolvedValue(keyOwnedByDifferentUser);

      await expect(
        service.rotateApiKey(mockUser.id, existingKeyId),
      ).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('Error Handling', () => {
    it('should handle database errors in generateApiKey', async () => {
      const databaseError = new Error('Database connection failed');
      userRepository.findOne.mockRejectedValue(databaseError);

      await expect(
        service.generateApiKey(mockUser.id, ['read']),
      ).rejects.toThrow('Database connection failed');
    });

    it('should handle crypto errors in validateApiKey', async () => {
      const cryptoError = new Error('Crypto operation failed');
      jest.spyOn(crypto, 'createHash').mockImplementation(() => {
        throw cryptoError;
      });

      await expect(service.validateApiKey('test-key')).rejects.toThrow(
        'Crypto operation failed',
      );
    });

    it('should handle database errors in listUserApiKeys', async () => {
      const databaseError = new Error('Database query failed');
      apiKeyRepository.find.mockRejectedValue(databaseError);

      await expect(service.listUserApiKeys(mockUser.id)).rejects.toThrow(
        'Database query failed',
      );
    });
  });
});
