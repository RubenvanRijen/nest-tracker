import { User } from '@backend/entities/user/user.entity';
import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcryptjs';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private readonly testRepo: Repository<User>,
  ) {}

  async getUserByEmail(email: string): Promise<User | undefined> {
    const user = await this.testRepo.findOne({ where: { email } });
    return user ?? undefined;
  }

  async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, 10);
  }

  async comparePassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }

  async registerUser(email: string, password: string): Promise<User> {
    const existing = await this.testRepo.findOne({ where: { email } });
    if (existing) {
      throw new Error('User with this email already exists');
    }
    const passwordHash = await this.hashPassword(password);
    const user = this.testRepo.create({ email, passwordHash });
    // TODO: Encrypt 2FA secret before saving if needed
    return await this.testRepo.save(user);
  }
}
