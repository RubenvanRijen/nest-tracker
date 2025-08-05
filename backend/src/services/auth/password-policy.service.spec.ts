import { Test, TestingModule } from '@nestjs/testing';
import { PasswordPolicyService } from './password-policy.service';

describe('PasswordPolicyService', () => {
  let service: PasswordPolicyService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [PasswordPolicyService],
    }).compile();

    service = module.get<PasswordPolicyService>(PasswordPolicyService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('isCommonPassword', () => {
    it('should identify common passwords', () => {
      const commonPasswords = [
        'password',
        'password123',
        '123456',
        'qwerty',
        'admin',
        'welcome',
      ];

      commonPasswords.forEach(password => {
        expect(service.isCommonPassword(password)).toBe(true);
      });
    });

    it('should not flag strong passwords as common', () => {
      const strongPasswords = [
        'Tr0ub4dor&3',
        'correcthorsebatterystaple',
        'P@$$w0rd!2023',
        'veryUniquePassword123!',
      ];

      strongPasswords.forEach(password => {
        expect(service.isCommonPassword(password)).toBe(false);
      });
    });

    it('should be case insensitive', () => {
      expect(service.isCommonPassword('PASSWORD')).toBe(true);
      expect(service.isCommonPassword('Password')).toBe(true);
      expect(service.isCommonPassword('password')).toBe(true);
    });
  });

  describe('validatePassword', () => {
    it('should validate strong passwords', () => {
      const strongPasswords = [
        'StrongP@ss1',
        'Tr0ub4dor&3',
        'P@$$w0rd!2023',
      ];

      strongPasswords.forEach(password => {
        const result = service.validatePassword(password);
        expect(result.valid).toBe(true);
      });
    });

    it('should reject passwords that are too short', () => {
      const result = service.validatePassword('Sh0rt!');
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('at least 8 characters');
    });

    it('should reject passwords without lowercase letters', () => {
      const result = service.validatePassword('PASSWORD123!');
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('lowercase letter');
    });

    it('should reject passwords without uppercase letters', () => {
      const result = service.validatePassword('password123!');
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('uppercase letter');
    });

    it('should reject passwords without digits', () => {
      const result = service.validatePassword('Password!');
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('digit');
    });

    it('should reject passwords without special characters', () => {
      const result = service.validatePassword('Password123');
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('special character');
    });

    it('should reject common passwords even if they meet complexity requirements', () => {
      // A common password that meets all other requirements
      const result = service.validatePassword('Password123!');
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('common');
    });
  });
});