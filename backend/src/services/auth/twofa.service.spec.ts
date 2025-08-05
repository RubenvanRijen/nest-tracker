import { Test, TestingModule } from '@nestjs/testing';
import { TwoFaService } from './twofa.service';
import * as speakeasy from 'speakeasy';

describe('TwoFaService', () => {
  let service: TwoFaService;

  // Mock environment variables
  const originalEnv = process.env;

  beforeEach(async () => {
    // Setup environment variables for testing
    process.env.TWOFA_ENCRYPT_KEY =
      'this-is-a-test-key-that-is-at-least-32-chars';
    process.env.TWOFA_ENCRYPT_SALT = 'test-salt-16-chars';

    const module: TestingModule = await Test.createTestingModule({
      providers: [TwoFaService],
    }).compile();

    service = module.get<TwoFaService>(TwoFaService);
  });

  afterEach(() => {
    // Restore original environment
    process.env = originalEnv;
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('2FA Secret Generation', () => {
    it('should generate a valid 2FA secret', () => {
      const email = 'test@example.com';
      const result = service.generate2faSecret(email);

      expect(result).toHaveProperty('secret');
      expect(result).toHaveProperty('otpauthUrl');
      expect(result.secret.length).toBeGreaterThanOrEqual(16);
      expect(result.otpauthUrl).toContain(email);
    });

    it('should rotate a 2FA secret', () => {
      const email = 'test@example.com';
      const result = service.rotate2faSecret(email);

      expect(result).toHaveProperty('secret');
      expect(result).toHaveProperty('otpauthUrl');
    });
  });

  describe('Secret Encryption', () => {
    it('should encrypt and decrypt a secret correctly', () => {
      const originalSecret = 'ABCDEFGHIJKLMNOP';
      const encrypted = service.encryptSecret(originalSecret);
      const decrypted = service.decryptSecret(encrypted);

      expect(encrypted).not.toEqual(originalSecret);
      expect(decrypted).toEqual(originalSecret);
    });
  });

  describe('Token Verification', () => {
    it('should verify a valid token', () => {
      // Generate a test secret
      const secret = speakeasy.generateSecret({ length: 20 }).base32;

      // Generate a valid token
      const token = speakeasy.totp({
        secret,
        encoding: 'base32',
      });

      const result = service.verify2faToken(secret, token);
      expect(result).toBe(true);
    });

    it('should reject an invalid token', () => {
      const secret = speakeasy.generateSecret({ length: 20 }).base32;
      const invalidToken = '123456'; // Not generated from the secret

      const result = service.verify2faToken(secret, invalidToken);
      expect(result).toBe(false);
    });
  });

  describe('Backup Codes', () => {
    it('should generate the correct number of backup codes', () => {
      const { plainCodes, hashedCodes } = service.generateBackupCodes();

      // Check if we have the expected number of codes (10 by default)
      expect(plainCodes.length).toBe(10);
      expect(hashedCodes.length).toBe(10);

      // Check format of plain codes (should be like XXXX-XXXX)
      plainCodes.forEach((code) => {
        expect(code).toMatch(/^[A-Z0-9]{4}-[A-Z0-9]{4}$/);
      });
    });

    it('should verify a valid backup code', () => {
      const { plainCodes, hashedCodes } = service.generateBackupCodes();

      // Try to verify the first code
      const codeIndex = service.verifyBackupCode(plainCodes[0], hashedCodes);
      expect(codeIndex).toBe(0);
    });

    it('should reject an invalid backup code', () => {
      const { hashedCodes } = service.generateBackupCodes();

      // Try to verify an invalid code
      const codeIndex = service.verifyBackupCode('INVALID-CODE', hashedCodes);
      expect(codeIndex).toBe(-1);
    });
  });
});
