import { User } from '@backend/entities/user/user.entity';
import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  InternalServerErrorException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as speakeasy from 'speakeasy';
import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
} from 'crypto';

@Injectable()
export class AuthService {
  private readonly encryptionKey: Buffer;

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly jwtService: JwtService,
  ) {
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
    return scryptSync(keySource, salt, 32);
  }

  generateJwt(user: User): string {
    return this.jwtService.sign({
      sub: user.id,
      email: user.email,
      roles: user.roles ?? [],
    });
  }

  /**
   * Handles login logic, including password and 2FA verification.
   */
  async loginUser(
    email: string,
    password: string,
    token?: string,
  ): Promise<{ user: User; jwt: string }> {
    const user = await this.getUserByEmail(email);
    if (!user || !user.passwordHash) {
      throw new UnauthorizedException('Invalid credentials');
    }
    const valid = await this.comparePassword(password, user.passwordHash);
    if (!valid) {
      throw new UnauthorizedException('Invalid credentials');
    }
    if (user.twoFaSecret) {
      if (!token) {
        throw new BadRequestException('2FA token required');
      }
      try {
        const secret = this.decryptSecret(user.twoFaSecret);
        const is2faValid = this.verify2faToken(secret, token);
        if (!is2faValid) {
          throw new UnauthorizedException('Invalid 2FA token');
        }
      } catch {
        // Handle decryption errors gracefully (e.g., if the data was tampered with)
        throw new UnauthorizedException('Invalid 2FA token');
      }
    }
    return { user, jwt: this.generateJwt(user) };
  }

  /**
   * Public method to save/update a user entity.
   */
  async saveUser(user: User): Promise<User> {
    return await this.userRepository.save(user);
  }

  async getUserByEmail(email: string): Promise<User | undefined> {
    const user = await this.userRepository.findOne({ where: { email } });
    return user ?? undefined;
  }

  async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, 12);
  }

  async comparePassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }

  async registerUser(email: string, password: string): Promise<User> {
    const existing = await this.userRepository.findOne({ where: { email } });
    if (existing) {
      throw new BadRequestException('User with this email already exists');
    }
    const passwordHash = await this.hashPassword(password);
    const user = this.userRepository.create({ email, passwordHash });
    return await this.userRepository.save(user);
  }

  /**
   * Encrypt a string using AES-256-GCM. Returns hex string with IV, tag, and ciphertext.
   * Store as hex: iv:tag:encrypted
   */
  encryptSecret(secret: string): string {
    const iv = randomBytes(12); // GCM standard IV size is 12 bytes
    const cipher = createCipheriv('aes-256-gcm', this.encryptionKey, iv);
    const encrypted = Buffer.concat([cipher.update(secret), cipher.final()]);
    const tag = cipher.getAuthTag();
    // Store as hex: iv:tag:encrypted
    return `${iv.toString('hex')}:${tag.toString('hex')}:${encrypted.toString('hex')}`;
  }

  /**
   * Decrypt a string using AES-256-CTR. Expects base64 string with IV prepended.
   */
  decryptSecret(data: string): string {
    // GCM format: iv:tag:encrypted
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

  /**
   * Generate a TOTP secret for 2FA setup.
   */
  generate2faSecret(email: string): { secret: string; otpauthUrl: string } {
    const secretObj = speakeasy.generateSecret({
      name: email,
      length: 32,
      issuer: 'NestTracker',
    });
    return {
      secret: secretObj.base32,
      otpauthUrl: secretObj.otpauth_url,
    };
  }

  /**
   * Verify a TOTP token against a user's secret.
   */
  verify2faToken(secret: string, token: string): boolean {
    return Boolean(
      speakeasy.totp.verify({
        secret,
        encoding: 'base32',
        token,
        window: 1, // allow +/- 30s
      }),
    );
  }
}
