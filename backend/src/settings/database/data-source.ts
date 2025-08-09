import { Environment } from '@backend/enums/environment/environment.enum';
import { DataSourceOptions } from 'typeorm';

const NODE_ENV = process.env.NODE_ENV ?? 'development';
const isTest = NODE_ENV?.toLowerCase() === Environment.Test.toLowerCase();

const DATABASE_URL = isTest
  ? (process.env.DATABASE_URL_TEST ?? process.env.DATABASE_URL)
  : process.env.DATABASE_URL;

// Allow tests to isolate by Postgres schema per test file
const TEST_SCHEMA = isTest ? process.env.TEST_SCHEMA : undefined;

export const dataSourceOptions: DataSourceOptions = {
  type: 'postgres',
  url: DATABASE_URL,
  schema: TEST_SCHEMA, // only effective for Postgres; undefined in non-test
  entities: [__dirname + '/../../../**/*.entity.{ts,js}'],
  // Use migrations in all environments to keep parity across dev/test/prod
  synchronize: false,
  dropSchema: false,
  migrations: [__dirname + '/../../../migrations/*{.ts,.js}'],
};
