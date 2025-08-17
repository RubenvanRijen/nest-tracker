import 'reflect-metadata';
import { DataSource } from 'typeorm';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import datasource from '../src/settings/database/typeorm.datasource';
import { runTestSeed } from '../src/seeds/test-seed';

// Simple env loader for .env.testing if running in test and vars missing
function ensureTestingEnvLoaded() {
  process.env.NODE_ENV = 'test';
  if (!process.env.DATABASE_URL_TEST && !process.env.DATABASE_URL) {
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

// Keep a reference to the schema and data source for teardown and optional test access
let schemaName: string | undefined;

// Expose a getter for tests if they need direct access
declare global {
  // eslint-disable-next-line no-var
  var __TEST_DS__: DataSource | undefined;
}

beforeAll(async () => {
  ensureTestingEnvLoaded();
  // generate unique schema per file to allow parallel isolated execution
  schemaName = `t_${crypto.randomBytes(6).toString('hex')}`;
  process.env.TEST_SCHEMA = schemaName;

  // Initialize a new DataSource instance bound to this schema
  await datasource.initialize();

  // Ensure schema exists explicitly
  await datasource.query(`CREATE SCHEMA IF NOT EXISTS "${schemaName}"`);
  // Ensure search_path is set for this connection (helps when migrations don't schema-qualify)
  await datasource.query(`SET search_path TO "${schemaName}", public`);

  // Run migrations within this connection/schema
  await datasource.runMigrations();

  // Seed baseline data
  await runTestSeed(datasource);

  // eslint-disable-next-line no-console
  console.log(`[test-setup] Initialized schema: ${schemaName}`);

  global.__TEST_DS__ = datasource;
});

afterAll(async () => {
  try {
    if (datasource.isInitialized) {
      // Switch to public schema to allow dropping the test schema
      await datasource.query('SET search_path TO public');
      if (schemaName) {
        await datasource.query(`DROP SCHEMA IF EXISTS "${schemaName}" CASCADE`);
      }
    }
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error('Error during test schema teardown:', e);
  } finally {
    if (datasource.isInitialized) {
      await datasource.destroy();
    }
    delete (global as any).__TEST_DS__;
    delete process.env.TEST_SCHEMA;
  }
});
