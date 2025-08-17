import path from 'path';
import 'reflect-metadata';
import dotenv from 'dotenv';
import { DataSource } from 'typeorm';

// Load repo-root .env (project root is three levels up from this script)
dotenv.config({ path: path.resolve(__dirname, '../../../.env') });

// Sanitize common .env mistakes BEFORE importing the data-source so it reads the cleaned value.
const rawDb = process.env.DATABASE_URL;
if (typeof rawDb === 'string') {
  const cleaned = rawDb
    .trim()
    .replace(/^['"]|['"]$/g, '')
    .replace(/\r?\n/g, '');
  process.env.DATABASE_URL = cleaned;
}

// Import dataSourceOptions after dotenv has loaded and env vars sanitized so it picks up the corrected URL.
// Use require() here to ensure the module reads process.env at runtime (not at module hoist time).

const { dataSourceOptions } = require('../settings/database/data-source') as {
  dataSourceOptions: any;
};

function debugEnv() {
  let raw = process.env.DATABASE_URL;
  // sanitize common issues: surrounding quotes and trailing CR/LF
  if (typeof raw === 'string') {
    raw = raw
      .trim()
      .replace(/^['"]|['"]$/g, '')
      .replace(/\r?\n/g, '');
    process.env.DATABASE_URL = raw;
  }
  console.log('DATABASE_URL (raw):', JSON.stringify(raw));
  if (!raw) {
    console.warn('DATABASE_URL is not set (loaded .env?).');
    return null;
  }

  try {
    const url = new URL(raw);
    // show username/password details (length and type)
    const pw = url.password;
    console.log('Parsed host:', url.hostname);
    console.log('Parsed port:', url.port);
    console.log(
      'Parsed database:',
      url.pathname?.replace(/^\//, '') || '(none)',
    );
    console.log('Parsed username:', JSON.stringify(url.username));
    console.log('Parsed password (stringified):', JSON.stringify(pw));
    console.log('Password typeof:', typeof pw, 'length:', pw?.length ?? 0);

    return url;
  } catch (err) {
    console.error(
      'Failed to parse DATABASE_URL with URL parser:',
      err.message ?? err,
    );
    return null;
  }
}

async function main() {
  const url = debugEnv();

  // Optional override to test connecting to localhost without editing .env
  const overrideHost = process.env.OVERRIDE_DB_HOST;
  if (overrideHost) {
    console.log(
      'OVERRIDE_DB_HOST is set, will attempt connection to host:',
      overrideHost,
    );
    // build a new connection URL string by replacing hostname
    if (url) {
      url.hostname = overrideHost;
      // also prefer localhost port if provided via env
      if (process.env.OVERRIDE_DB_PORT) url.port = process.env.OVERRIDE_DB_PORT;
      process.env.DATABASE_URL = url.toString();
      console.log('Using overridden DATABASE_URL:', process.env.DATABASE_URL);
    }
  }

  // Create DataSource using the current (possibly overridden) DATABASE_URL so the
  // DataSource connects to the same host as the direct pg Client diagnostic.
  const effectiveUrl = process.env.DATABASE_URL;
  const ds = new DataSource({
    ...dataSourceOptions,
    url: effectiveUrl,
  });
  // Extra diagnostics: try connecting with 'pg' directly to see how the driver sees the password.
  if (url) {
    try {
      const { Client } = require('pg');
      console.warn(
        'Attempting direct pg Client connect for extra diagnostics...',
      );
      console.warn(
        'typeof process.env.DATABASE_URL:',
        typeof process.env.DATABASE_URL,
      );
      console.warn(
        'URL password typeof (from URL parser):',
        typeof url.password,
      );
      console.warn('URL password JSON:', JSON.stringify(url.password));
      const pgClient = new Client({
        connectionString: process.env.DATABASE_URL,
      });
      await pgClient.connect();
      console.warn('✅ pg Client connected');
      await pgClient.end();
    } catch (pgErr: any) {
      console.error(
        'pg client connection failed:',
        pgErr && pgErr.message ? pgErr.message : pgErr,
      );
      if (
        pgErr &&
        pgErr.message &&
        pgErr.message.includes('client password must be a string')
      ) {
        console.error('pg driver reports SASL password type error');
      }
    }
  }
  try {
    await ds.initialize();
    console.warn('✅ DataSource initialized');
    const res = await ds.query('SELECT version()');
    console.warn('DB response:', res);
  } catch (err: any) {
    // Extra debug for common pg auth/parsing issues
    console.error(
      '❌ DB connection failed:',
      err && err.message ? err.message : err,
    );
    if (
      err &&
      err.message &&
      err.message.includes('client password must be a string')
    ) {
      console.error(
        'Detected SASL password error — check that DATABASE_URL password is present and a plain string (no surrounding quotes or newlines).',
      );
    }
    // print current effective DATABASE_URL (masked password)
    try {
      const eff = process.env.DATABASE_URL ?? '(none)';
      const masked = eff.replace(/:(?:[^:@]+)@/, ':*****@');
      console.error('Effective DATABASE_URL (masked):', masked);
    } catch {}
    process.exitCode = 1;
  } finally {
    try {
      await ds.destroy();
    } catch (destroyErr) {
      // ignore
    }
  }
}

void main();
