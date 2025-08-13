import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { JwtService } from '@nestjs/jwt';
import { Repository } from 'typeorm';
import {
  UnauthorizedException,
  BadRequestException,
  ForbiddenException,
} from '@nestjs/common';
import * as bcrypt from 'bcryptjs';
import { AuthService } from './auth.service';
import { User } from '@backend/entities/user/user.entity';
import { PasswordPolicyService } from './password-policy.service';

describe('AuthService', () => {
  let service: AuthService;
  let userRepository: jest.Mocked<Repository<User>>;
  let jwtService: jest.Mocked<JwtService>;
  let passwordPolicyService: jest.Mocked<PasswordPolicyService>;

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

  beforeEach(async () => {
    const mockUserRepository = {
      findOne: jest.fn(),
      save: jest.fn(),
      create: jest.fn(),
    };

    const mockJwtService = {
      sign: jest.fn(),
      verify: jest.fn(),
    };

    const mockPasswordPolicyService = {
      validatePassword: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: getRepositoryToken(User),
          useValue: mockUserRepository,
        },
        {
          provide: JwtService,
          useValue: mockJwtService,
        },
        {
          provide: PasswordPolicyService,
          useValue: mockPasswordPolicyService,
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    userRepository = module.get(getRepositoryToken(User));
    jwtService = module.get(JwtService);
    passwordPolicyService = module.get(PasswordPolicyService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('generateJwt', () => {
    it('should generate a JWT token for a user', () => {
      const mockToken = 'jwt-token-123';
      jwtService.sign.mockReturnValue(mockToken);

      const result = service.generateJwt(mockUser);

      expect(jwtService.sign).toHaveBeenCalledWith({
        userId: mockUser.id,
        email: mockUser.email,
        roles: mockUser.roles,
      });
      expect(result).toBe(mockToken);
    });
  });

  describe('generateRefreshToken', () => {
    it('should generate and save a refresh token for a user', async () => {
      const mockRefreshToken = 'refresh-token-123';
      const updatedUser = { ...mockUser };
      userRepository.save.mockResolvedValue(updatedUser);

      // Mock crypto.randomBytes
      jest
        .spyOn(require('crypto'), 'randomBytes')
        .mockReturnValue(Buffer.from(mockRefreshToken));

      const result = await service.generateRefreshToken(mockUser);

      expect(userRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          id: mockUser.id,
          refreshTokenHash: expect.any(String),
          refreshTokenExpiresAt: expect.any(Date),
        }),
      );
      expect(result).toBe(mockRefreshToken);
    });
  });

  describe('refreshJwtToken', () => {
    it('should refresh JWT token with valid refresh token', async () => {
      const refreshToken = 'valid-refresh-token';
      const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
      const userWithRefreshToken = {
        ...mockUser,
        refreshTokenHash: hashedRefreshToken,
        refreshTokenExpiresAt: new Date(Date.now() + 86400000), // 1 day from now
      };

      const mockJwtToken = 'new-jwt-token';
      userRepository.findOne.mockResolvedValue(userWithRefreshToken);
      jwtService.sign.mockReturnValue(mockJwtToken);

      const result = await service.refreshJwtToken(mockUser.id, refreshToken);

      expect(result).toEqual({
        accessToken: mockJwtToken,
        user: expect.objectContaining({
          id: mockUser.id,
          email: mockUser.email,
        }),
      });
    });

    it('should throw UnauthorizedException for invalid user', async () => {
      userRepository.findOne.mockResolvedValue(null);

      await expect(
        service.refreshJwtToken('invalid-user-id', 'refresh-token'),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException for expired refresh token', async () => {
      const userWithExpiredToken = {
        ...mockUser,
        refreshTokenHash: 'hashed-token',
        refreshTokenExpiresAt: new Date(Date.now() - 86400000), // 1 day ago
      };

      userRepository.findOne.mockResolvedValue(userWithExpiredToken);

      await expect(
        service.refreshJwtToken(mockUser.id, 'refresh-token'),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException for invalid refresh token', async () => {
      const userWithRefreshToken = {
        ...mockUser,
        refreshTokenHash: await bcrypt.hash('different-token', 10),
        refreshTokenExpiresAt: new Date(Date.now() + 86400000),
      };

      userRepository.findOne.mockResolvedValue(userWithRefreshToken);

      await expect(
        service.refreshJwtToken(mockUser.id, 'wrong-refresh-token'),
      ).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('loginUser', () => {
    it('should successfully login user with valid credentials', async () => {
      const email = 'test@example.com';
      const password = 'ValidPassword123!';
      const hashedPassword = await bcrypt.hash(password, 10);
      const userWithPassword = { ...mockUser, passwordHash: hashedPassword };

      const mockJwtToken = 'jwt-token';
      const mockRefreshToken = 'refresh-token';

      userRepository.findOne.mockResolvedValue(userWithPassword);
      jwtService.sign.mockReturnValue(mockJwtToken);
      jest
        .spyOn(service, 'generateRefreshToken')
        .mockResolvedValue(mockRefreshToken);

      const result = await service.loginUser(email, password);

      expect(result).toEqual({
        accessToken: mockJwtToken,
        refreshToken: mockRefreshToken,
        user: expect.objectContaining({
          id: mockUser.id,
          email: mockUser.email,
        }),
      });
    });

    it('should throw UnauthorizedException for non-existent user', async () => {
      userRepository.findOne.mockResolvedValue(null);

      await expect(
        service.loginUser('nonexistent@example.com', 'password'),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException for invalid password', async () => {
      const userWithPassword = {
        ...mockUser,
        passwordHash: await bcrypt.hash('different-password', 10),
      };
      userRepository.findOne.mockResolvedValue(userWithPassword);

      await expect(
        service.loginUser(mockUser.email, 'wrong-password'),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw ForbiddenException for user with 2FA enabled', async () => {
      const userWith2FA = { ...mockUser, twoFaSecret: 'encrypted-secret' };
      userRepository.findOne.mockResolvedValue(userWith2FA);

      await expect(
        service.loginUser(mockUser.email, 'ValidPassword123!'),
      ).rejects.toThrow(ForbiddenException);
    });
  });

  describe('registerUser', () => {
    it('should successfully register a new user', async () => {
      const email = 'newuser@example.com';
      const password = 'ValidPassword123!';
      const newUser = { ...mockUser, email, id: 'new-user-id' };

      userRepository.findOne.mockResolvedValue(null); // User doesn't exist
      userRepository.create.mockReturnValue(newUser);
      userRepository.save.mockResolvedValue(newUser);
      passwordPolicyService.validatePassword.mockReturnValue(true);

      const result = await service.registerUser(email, password);

      expect(passwordPolicyService.validatePassword).toHaveBeenCalledWith(
        password,
      );
      expect(userRepository.create).toHaveBeenCalledWith({
        email,
        passwordHash: expect.any(String),
        roles: ['user'],
      });
      expect(result).toEqual(newUser);
    });

    it('should throw BadRequestException for existing user', async () => {
      userRepository.findOne.mockResolvedValue(mockUser);

      await expect(
        service.registerUser(mockUser.email, 'ValidPassword123!'),
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw BadRequestException for invalid password policy', async () => {
      passwordPolicyService.validatePassword.mockReturnValue(false);

      await expect(
        service.registerUser('newuser@example.com', 'weak'),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('hashPassword', () => {
    it('should hash a password', async () => {
      const password = 'TestPassword123!';
      const hash = await service.hashPassword(password);

      expect(hash).toBeDefined();
      expect(hash).not.toBe(password);
      expect(await bcrypt.compare(password, hash)).toBe(true);
    });
  });

  describe('comparePassword', () => {
    it('should return true for matching password and hash', async () => {
      const password = 'TestPassword123!';
      const hash = await bcrypt.hash(password, 10);

      const result = await service.comparePassword(password, hash);

      expect(result).toBe(true);
    });

    it('should return false for non-matching password and hash', async () => {
      const password = 'TestPassword123!';
      const wrongPassword = 'WrongPassword123!';
      const hash = await bcrypt.hash(password, 10);

      const result = await service.comparePassword(wrongPassword, hash);

      expect(result).toBe(false);
    });
  });

  describe('getUserByEmail', () => {
    it('should return user by email', async () => {
      userRepository.findOne.mockResolvedValue(mockUser);

      const result = await service.getUserByEmail(mockUser.email);

      expect(userRepository.findOne).toHaveBeenCalledWith({
        where: { email: mockUser.email },
      });
      expect(result).toBe(mockUser);
    });

    it('should return null for non-existent user', async () => {
      userRepository.findOne.mockResolvedValue(null);

      const result = await service.getUserByEmail('nonexistent@example.com');

      expect(result).toBeNull();
    });
  });

  describe('saveUser', () => {
    it('should save and return user', async () => {
      const savedUser = { ...mockUser, email: 'updated@example.com' };
      userRepository.save.mockResolvedValue(savedUser);

      const result = await service.saveUser(savedUser);

      expect(userRepository.save).toHaveBeenCalledWith(savedUser);
      expect(result).toBe(savedUser);
    });
  });

  describe('_getUserWithPasswordByEmail', () => {
    it('should return user with password hash', async () => {
      const userWithPassword = { ...mockUser, passwordHash: 'hashed-password' };
      userRepository.findOne.mockResolvedValue(userWithPassword);

      const result = await service._getUserWithPasswordByEmail(mockUser.email);

      expect(userRepository.findOne).toHaveBeenCalledWith({
        where: { email: mockUser.email },
        select: [
          'id',
          'email',
          'passwordHash',
          'roles',
          'twoFaSecret',
          'refreshTokenHash',
          'refreshTokenExpiresAt',
        ],
      });
      expect(result).toBe(userWithPassword);
    });
  });

  describe('Error Handling', () => {
    it('should handle database errors gracefully', async () => {
      const databaseError = new Error('Database connection failed');
      userRepository.findOne.mockRejectedValue(databaseError);

      await expect(service.getUserByEmail('test@example.com')).rejects.toThrow(
        'Database connection failed',
      );
    });

    it('should handle bcrypt errors in password comparison', async () => {
      jest
        .spyOn(bcrypt, 'compare')
        .mockRejectedValue(new Error('Bcrypt error'));

      await expect(service.comparePassword('password', 'hash')).rejects.toThrow(
        'Bcrypt error',
      );
    });
  });
});
