import * as dotenv from 'dotenv';
import { join } from 'path';

// Load test environment variables before tests run
dotenv.config({
  path: join(__dirname, '../../.env.testing'),
});

// Ensure NODE_ENV is set to test
process.env.NODE_ENV = 'test';

// Set default test timeout
jest.setTimeout(30000);

// Global test setup
beforeAll(() => {
  console.log('🧪 Test environment initialized');
  console.log(
    `Database: ${process.env.DATABASE_URL_TEST || 'nesttracker_test'}`,
  );
});

afterAll(() => {
  console.log('🏁 Test environment cleanup completed');
});
