import {
  Injectable,
  InternalServerErrorException,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import * as speakeasy from 'speakeasy';
import {
  randomBytes,
  createCipheriv,
  createDecipheriv,
  scryptSync,
  createHash,
} from 'crypto';
import {
  BACKUP_CODE_COUNT,
  BACKUP_CODE_LENGTH,
  MIN_KEY_LENGTH,
  MIN_SALT_LENGTH,
} from '@backend/constants/auth';

@Injectable()
export class TwoFaService {
  private readonly encryptionKey: Buffer;
  private readonly logger = new Logger(TwoFaService.name);

  constructor() {
    this.encryptionKey = this.deriveEncryptionKey();
  }

  private deriveEncryptionKey(): Buffer {
    const keySource = process.env.TWOFA_ENCRYPT_KEY;
    const salt = process.env.TWOFA_ENCRYPT_SALT;
    if (!keySource || Buffer.byteLength(keySource, 'utf8') < MIN_KEY_LENGTH) {
      throw new InternalServerErrorException(
        'Encryption key (TWOFA_ENCRYPT_KEY) must be at least 32 bytes long.',
      );
    }
    if (!salt || Buffer.byteLength(salt, 'utf8') < MIN_SALT_LENGTH) {
      throw new InternalServerErrorException(
        'Encryption salt (TWOFA_ENCRYPT_SALT) must be at least 16 bytes long.',
      );
    }
    const derivedKey = scryptSync(keySource, salt, 32);
    if (!derivedKey || derivedKey.length !== 32) {
      throw new InternalServerErrorException(
        'Derived encryption key is not 32 bytes. Check your TWOFA_ENCRYPT_KEY and TWOFA_ENCRYPT_SALT values.',
      );
    }
    return derivedKey;
  }

  encryptSecret(secret: string): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.encryptionKey, iv);
    const encrypted = Buffer.concat([cipher.update(secret), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `${iv.toString('hex')}:${tag.toString('hex')}:${encrypted.toString('hex')}`;
  }

  decryptSecret(data: string): string {
    const parts = data.split(':');
    if (parts.length !== 3) {
      throw new UnauthorizedException('Invalid encrypted data format');
    }
    const [ivHex, tagHex, encryptedHex] = parts;
    const iv = Buffer.from(ivHex, 'hex');
    const tag = Buffer.from(tagHex, 'hex');
    const encrypted = Buffer.from(encryptedHex, 'hex');
    const decipher = createDecipheriv('aes-256-gcm', this.encryptionKey, iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([
      decipher.update(encrypted),
      decipher.final(),
    ]);
    return decrypted.toString();
  }

  generate2faSecret(email: string): { secret: string; otpauthUrl: string } {
    const secretObj = speakeasy.generateSecret({
      name: email,
      length: 32,
      issuer: 'NestTracker',
    });
    const base32Secret = secretObj.base32;
    const minEntropyBits = 160;
    const actualEntropyBits = base32Secret.length * 5;
    if (actualEntropyBits < minEntropyBits) {
      throw new InternalServerErrorException(
        `Generated 2FA secret does not meet minimum entropy requirements: ${actualEntropyBits} < ${minEntropyBits} bits.`,
      );
    }
    this.logger.log(`Generated new 2FA secret for: ${email}`);
    return { secret: base32Secret, otpauthUrl: secretObj.otpauth_url };
  }

  /**
   * Rotates a user's 2FA secret, generating a new one
   * @param email User's email for the new secret
   * @returns New secret and otpauth URL
   */
  rotate2faSecret(email: string): { secret: string; otpauthUrl: string } {
    this.logger.log(`Rotating 2FA secret for: ${email}`);
    return this.generate2faSecret(email);
  }

  verify2faToken(secret: string, token: string): boolean {
    return Boolean(
      speakeasy.totp.verify({
        secret,
        encoding: 'base32',
        token,
        window: 1,
      }),
    );
  }

  /**
   * Generates a set of backup codes for 2FA recovery
   * @returns Array of plain text backup codes and their hashed versions
   */
  generateBackupCodes(): { plainCodes: string[]; hashedCodes: string[] } {
    const plainCodes: string[] = [];
    const hashedCodes: string[] = [];

    for (let i = 0; i < BACKUP_CODE_COUNT; i++) {
      // Generate a random code with specified length
      const code = randomBytes(BACKUP_CODE_LENGTH / 2)
        .toString('hex')
        .toUpperCase();

      // Format the code with a hyphen in the middle for readability
      const formattedCode = `${code.substring(0, 4)}-${code.substring(4)}`;
      plainCodes.push(formattedCode);

      // Hash the code for storage
      const hashedCode = this.hashBackupCode(formattedCode);
      hashedCodes.push(hashedCode);
    }

    this.logger.log(`Generated ${plainCodes.length} backup codes`);
    return { plainCodes, hashedCodes };
  }

  /**
   * Hashes a backup code for secure storage
   * @param code The backup code to hash
   * @returns The hashed backup code
   */
  private hashBackupCode(code: string): string {
    return createHash('sha256').update(code).digest('hex');
  }

  /**
   * Verifies a backup code against a list of hashed codes
   * @param code The backup code to verify
   * @param hashedCodes Array of hashed backup codes
   * @returns The index of the matched code or -1 if no match
   */
  verifyBackupCode(code: string, hashedCodes: string[]): number {
    if (!code || !hashedCodes || hashedCodes.length === 0) {
      return -1;
    }

    const hashedCode = this.hashBackupCode(code);
    return hashedCodes.indexOf(hashedCode);
  }
}
