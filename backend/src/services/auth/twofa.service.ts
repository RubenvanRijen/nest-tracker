import { Injectable, InternalServerErrorException } from '@nestjs/common';
import * as speakeasy from 'speakeasy';
import {
  randomBytes,
  createCipheriv,
  createDecipheriv,
  scryptSync,
} from 'crypto';

@Injectable()
export class TwoFaService {
  private readonly encryptionKey: Buffer;

  constructor() {
    this.encryptionKey = this.deriveEncryptionKey();
  }

  private deriveEncryptionKey(): Buffer {
    const keySource = process.env.TWOFA_ENCRYPT_KEY;
    const salt = process.env.TWOFA_ENCRYPT_SALT;
    if (!keySource || keySource.length < 32) {
      throw new InternalServerErrorException(
        'Encryption key (TWOFA_ENCRYPT_KEY) must be at least 32 characters long.',
      );
    }
    if (!salt || salt.length < 16) {
      throw new InternalServerErrorException(
        'Encryption salt (TWOFA_ENCRYPT_SALT) must be at least 16 characters long.',
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
      throw new InternalServerErrorException('Invalid encrypted data format');
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
    return { secret: base32Secret, otpauthUrl: secretObj.otpauth_url };
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
}
