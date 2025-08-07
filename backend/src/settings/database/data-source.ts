import { DataSourceOptions } from 'typeorm';

const NODE_ENV = process.env.NODE_ENV ?? 'development';
const isTest = NODE_ENV === 'test';

const DATABASE_URL = isTest
  ? (process.env.DATABASE_URL_TEST ?? process.env.DATABASE_URL)
  : process.env.DATABASE_URL;

export const dataSourceOptions: DataSourceOptions = {
  type: 'postgres',
  url: DATABASE_URL,
  entities: [__dirname + '/../../../**/*.entity.{ts,js}'],
  // Use migrations in all environments to keep parity across dev/test/prod
  synchronize: false,
  dropSchema: false,
  migrations: [__dirname + '/../../../migrations/*{.ts,.js}'],
};
