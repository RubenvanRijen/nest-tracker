import 'reflect-metadata';
import { DataSource } from 'typeorm';
import dataSource from '@backend/settings/database/typeorm.datasource';
import { User } from '@backend/entities/user/user.entity';
import * as bcrypt from 'bcryptjs';
import * as fs from 'fs';
import * as path from 'path';

function loadTestingEnvIfNeeded() {
  const isTest = process.env.NODE_ENV === 'test';
  if (!isTest) return;
  // If DATABASE_URL_TEST isn't set, try loading from .env.testing (no external deps)
  if (!process.env.DATABASE_URL_TEST) {
    const envPath = path.resolve(process.cwd(), '.env.testing');
    if (fs.existsSync(envPath)) {
      const lines = fs.readFileSync(envPath, 'utf-8').split(/\r?\n/);
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const idx = trimmed.indexOf('=');
        if (idx > -1) {
          const key = trimmed.slice(0, idx).trim();
          const value = trimmed.slice(idx + 1).trim();
          if (!(key in process.env)) {
            process.env[key] = value;
          }
        }
      }
    }
  }
}

async function seed(ds: DataSource) {
  const userRepo = ds.getRepository(User);

  // Seed a baseline admin-like user that won't conflict with tests
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
    // eslint-disable-next-line no-console
    console.log(`Seeded user: ${email}`);
  } else {
    // eslint-disable-next-line no-console
    console.log(`User already seeded: ${email}`);
  }
}

void (async () => {
  try {
    loadTestingEnvIfNeeded();
    await dataSource.initialize();
    await seed(dataSource);
  } catch (err) {
    console.error('Seeding failed:', err);
    process.exitCode = 1;
  } finally {
    if (dataSource.isInitialized) {
      await dataSource.destroy();
    }
  }
})();
