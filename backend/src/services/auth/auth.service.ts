import { User } from '@backend/entities/user/user.entity';
import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  Logger,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

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

  async loginUser(
    email: string,
    password: string,
  ): Promise<{ user: User; jwt: string }> {
    // Use the dedicated method to fetch the user with their password hash
    const user = await this._getUserWithPasswordByEmail(email);
    if (!user || !user.passwordHash) {
      throw new UnauthorizedException('Invalid credentials');
    }
    const valid = await this.comparePassword(password, user.passwordHash);
    if (!valid) {
      throw new UnauthorizedException('Invalid credentials');
    }
    return { user, jwt: this.generateJwt(user) };
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
      throw new BadRequestException('User with this email already exists');
    }
    const passwordHash = await this.hashPassword(password);
    const user = this.userRepository.create({ email, passwordHash });
    return await this.userRepository.save(user);
  }
}
