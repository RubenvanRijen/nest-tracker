import { DataSource } from 'typeorm';
import { User } from '../entities/user/user.entity';
import * as bcrypt from 'bcryptjs';

/**
 * Minimal test seed to establish a known baseline across suites.
 * Extend as needed for test fixtures.
 */
export async function runTestSeed(ds: DataSource) {
  const userRepo = ds.getRepository(User);

  const email = 'seedadmin@example.com';
  const existing = await userRepo.findOne({ where: { email } });
  if (!existing) {
    const passwordHash = await bcrypt.hash('AdminP@ssw0rd123', 10);
    const user = userRepo.create({
      email,
      passwordHash,
      roles: ['admin'],
    });
    await userRepo.save(user);
  }
}
