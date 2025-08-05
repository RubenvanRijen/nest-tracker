import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class PasswordPolicyService {
  private readonly logger = new Logger(PasswordPolicyService.name);
  private commonPasswords: Set<string> = new Set();
  private readonly COMMON_PASSWORDS = [
    'password',
    'password123',
    '123456',
    '12345678',
    'qwerty',
    'admin',
    'welcome',
    'welcome123',
    'letmein',
    'abc123',
    'monkey',
    'dragon',
    'sunshine',
    'princess',
    'football',
    'baseball',
    'master',
    'superman',
    'batman',
    'trustno1',
    'iloveyou',
    '111111',
    '123123',
    '1234567890',
    'qwertyuiop',
    'asdfghjkl',
    'zxcvbnm',
    'admin123',
    'adminadmin',
    'passw0rd',
    'p@ssw0rd',
    'Password1',
    'Password123',
    'qwerty123',
  ];

  constructor() {
    this.initializeCommonPasswords();
  }

  private initializeCommonPasswords(): void {
    // Add the hardcoded common passwords to the set
    for (const password of this.COMMON_PASSWORDS) {
      this.commonPasswords.add(password.toLowerCase());
    }

    this.logger.log(
      `Initialized common password list with ${this.commonPasswords.size} entries`,
    );
  }

  /**
   * Checks if a password is common/weak
   * @param password The password to check
   * @returns true if the password is common/weak, false otherwise
   */
  isCommonPassword(password: string): boolean {
    const lowerPassword = password.toLowerCase();
    return this.commonPasswords.has(lowerPassword);
  }

  /**
   * Validates a password against the password policy
   * @param password The password to validate
   * @returns An object with validation result and reason if invalid
   */
  validatePassword(password: string): { valid: boolean; reason?: string } {
    // Check minimum length
    if (password.length < 8) {
      return {
        valid: false,
        reason: 'Password must be at least 8 characters long',
      };
    }

    // Check for lowercase letters
    if (!/[a-z]/.test(password)) {
      return {
        valid: false,
        reason: 'Password must contain at least one lowercase letter',
      };
    }

    // Check for uppercase letters
    if (!/[A-Z]/.test(password)) {
      return {
        valid: false,
        reason: 'Password must contain at least one uppercase letter',
      };
    }

    // Check for digits
    if (!/\d/.test(password)) {
      return {
        valid: false,
        reason: 'Password must contain at least one digit',
      };
    }

    // Check for special characters
    if (!/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password)) {
      return {
        valid: false,
        reason: 'Password must contain at least one special character',
      };
    }

    // Check if it's a common password
    if (this.isCommonPassword(password)) {
      return {
        valid: false,
        reason: 'Password is too common and easily guessable',
      };
    }

    return { valid: true };
  }
}
