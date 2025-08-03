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
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly jwtService: JwtService,
  ) {}

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
      const secret = this.decryptSecret(user.twoFaSecret);
      const is2faValid = this.verify2faToken(secret, token);
      if (!is2faValid) {
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
    return bcrypt.hash(password, 10);
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
   * Encrypt a string using AES-256-CTR. Returns base64 string with IV prepended.
   */
  encryptSecret(secret: string): string {
    const keySource = process.env.TWOFA_ENCRYPT_KEY;
    if (!keySource) {
      throw new InternalServerErrorException(
        'Encryption key (TWOFA_ENCRYPT_KEY) must be set in environment',
      );
    }
    const salt = process.env.TWOFA_ENCRYPT_SALT;
    if (!salt) {
      throw new InternalServerErrorException(
        'Encryption salt (TWOFA_ENCRYPT_SALT) must be set in environment',
      );
    }
    const key = scryptSync(keySource, salt, 32);
    const iv = randomBytes(16);
    const cipher = createCipheriv('aes-256-ctr', key, iv);
    const encrypted = Buffer.concat([cipher.update(secret), cipher.final()]);
    // Store as base64: iv:encrypted
    return `${iv.toString('hex')}:${encrypted.toString('hex')}`;
  }

  /**
   * Decrypt a string using AES-256-CTR. Expects base64 string with IV prepended.
   */
  decryptSecret(data: string): string {
    const [ivHex, encryptedHex] = data.split(':');
    const keySource = process.env.TWOFA_ENCRYPT_KEY;
    if (!keySource) {
      throw new InternalServerErrorException(
        'Encryption key (TWOFA_ENCRYPT_KEY) must be set in environment',
      );
    }
    const salt = process.env.TWOFA_ENCRYPT_SALT;
    if (!salt) {
      throw new InternalServerErrorException(
        'Encryption salt (TWOFA_ENCRYPT_SALT) must be set in environment',
      );
    }
    const key = scryptSync(keySource, salt, 32);
    const iv = Buffer.from(ivHex, 'hex');
    const encrypted = Buffer.from(encryptedHex, 'hex');
    const decipher = createDecipheriv('aes-256-ctr', key, iv);
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
