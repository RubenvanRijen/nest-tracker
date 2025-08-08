import 'reflect-metadata';
import dataSource from '@backend/settings/database/typeorm.datasource';
import * as fs from 'fs';
import * as path from 'path';
import { runTestSeed } from './test-seed';

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

void (async () => {
  try {
    loadTestingEnvIfNeeded();
    await dataSource.initialize();
    await runTestSeed(dataSource);
  } catch (err) {
    console.error('Seeding failed:', err);
    process.exitCode = 1;
  } finally {
    if (dataSource.isInitialized) {
      await dataSource.destroy();
    }
  }
})();
