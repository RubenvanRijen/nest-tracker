import { User } from '@backend/entities/user/user.entity';
import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  Logger,
  ForbiddenException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { randomBytes } from 'crypto';
import { PasswordPolicyService } from '@backend/services/auth/password-policy.service';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly jwtService: JwtService,
    private readonly passwordPolicyService: PasswordPolicyService,
  ) {}

  generateJwt(user: User): string {
    return this.jwtService.sign({
      sub: user.id,
      email: user.email,
      roles: user.roles ?? [],
    });
  }

  /**
   * Generates a refresh token for the user and stores its hash in the database.
   * @param user The user to generate a refresh token for
   * @returns The generated refresh token
   */
  async generateRefreshToken(user: User): Promise<string> {
    // Generate a secure random token
    const refreshToken = randomBytes(40).toString('hex');

    // Hash the token before storing it
    const refreshTokenHash = await this.hashPassword(refreshToken);
    const refreshTokenExpiryDays = 30;

    // Set expiration date (30 days from now)
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + refreshTokenExpiryDays);

    // Update user with new refresh token hash and expiration
    user.refreshTokenHash = refreshTokenHash;
    user.refreshTokenExpiresAt = expiresAt;
    await this.saveUser(user);

    return refreshToken;
  }

  /**
   * Validates a refresh token and returns a new JWT if valid.
   * @param userId The user ID from the token
   * @param refreshToken The refresh token to validate
   * @returns A new JWT token
   */
  async refreshJwtToken(
    userId: string,
    refreshToken: string,
  ): Promise<{ token: string; refreshToken: string }> {
    // Get user with refresh token hash
    const user = await this.userRepository.findOne({
      where: { id: userId },
      select: [
        'id',
        'email',
        'refreshTokenHash',
        'refreshTokenExpiresAt',
        'roles',
      ],
    });

    if (!user || !user.refreshTokenHash || !user.refreshTokenExpiresAt) {
      this.logger.warn(
        `Refresh token attempt with invalid user or missing token: ${userId}`,
      );
      throw new ForbiddenException('Session expired, please login again');
    }

    // Check if token is expired
    if (new Date() > user.refreshTokenExpiresAt) {
      // Clear expired token
      user.refreshTokenHash = null;
      user.refreshTokenExpiresAt = null;
      await this.saveUser(user);
      this.logger.warn(`Expired refresh token used for user: ${userId}`);
      throw new ForbiddenException('Session expired, please login again');
    }

    // Verify the token matches
    const isValid = await this.comparePassword(
      refreshToken,
      user.refreshTokenHash,
    );
    if (!isValid) {
      this.logger.warn(`Invalid refresh token used for user: ${userId}`);
      throw new ForbiddenException('Session expired, please login again');
    }

    // Generate new tokens
    const newJwt = this.generateJwt(user);
    const newRefreshToken = await this.generateRefreshToken(user);

    this.logger.log(`Refresh token successfully used for user: ${userId}`);
    return { token: newJwt, refreshToken: newRefreshToken };
  }
  /**
   * Handles login logic, including password and 2FA verification.
   */
  /**
   * Retrieves a user by email, including the password hash for authentication purposes.
   * This method is specifically for login and should not be used for other queries.
   */
  private async _getUserWithPasswordByEmail(
    email: string,
  ): Promise<User | null> {
    return this.userRepository.findOne({
      where: { email },
      select: [
        'id',
        'email',
        'passwordHash',
        'apiKeyHash',
        'twoFaSecret',
        'passkeyId',
        'roles',
      ],
    });
  }

  /**
   * Authenticates a user with email and password.
   * If successful, generates JWT and refresh tokens.
   */
  async loginUser(
    email: string,
    password: string,
  ): Promise<{ user: User; jwt: string; refreshToken?: string }> {
    // Use the dedicated method to fetch the user with their password hash
    const user = await this._getUserWithPasswordByEmail(email);
    if (!user || !user.passwordHash) {
      this.logger.warn(`Failed login attempt for email: ${email}`);
      throw new UnauthorizedException('Authentication failed');
    }

    const valid = await this.comparePassword(password, user.passwordHash);
    if (!valid) {
      this.logger.warn(
        `Failed login attempt (invalid password) for user: ${user.id}`,
      );
      throw new UnauthorizedException('Authentication failed');
    }

    // Generate JWT token
    const jwt = this.generateJwt(user);

    // For 2FA users, don't generate refresh token yet (will be generated after 2FA verification)
    if (user.twoFaSecret) {
      return { user, jwt };
    }

    // Generate refresh token for non-2FA users
    const refreshToken = await this.generateRefreshToken(user);

    this.logger.log(`Successful login for user: ${user.id}`);
    return { user, jwt, refreshToken };
  }

  /**
   * Public method to save/update a user entity.
   */
  async saveUser(user: User): Promise<User> {
    return await this.userRepository.save(user);
  }

  async getUserByEmail(email: string): Promise<User | null> {
    // General user lookup, does NOT select passwordHash
    return await this.userRepository.findOne({ where: { email } });
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
      this.logger.warn(`Registration attempt with existing email: ${email}`);
      throw new BadRequestException('User with this email already exists');
    }

    // Check if password is common or weak
    const passwordValidation =
      this.passwordPolicyService.validatePassword(password);
    if (!passwordValidation.valid) {
      this.logger.warn(
        `Registration attempt with weak password: ${passwordValidation.reason}`,
      );
      throw new BadRequestException(passwordValidation.reason);
    }

    const passwordHash = await this.hashPassword(password);
    const user = this.userRepository.create({ email, passwordHash });
    const savedUser = await this.userRepository.save(user);
    this.logger.log(`User registered successfully: ${savedUser.id}`);
    return savedUser;
  }
}
