import { DataSourceOptions } from 'typeorm';
import {
  Environment,
  environmentFromString,
} from '@backend/enums/environment/environment.enum';

const getTestDatabaseConfig = (): Partial<DataSourceOptions> => {
  // Parse DATABASE_URL_TEST if present
  const testDbUrl = process.env.DATABASE_URL_TEST;
  if (testDbUrl) {
    const url = new URL(testDbUrl);
    return {
      host: url.hostname,
      port: parseInt(url.port || '5432'),
      username: url.username,
      password: url.password,
      database: url.pathname.slice(1), // Remove leading slash
    };
  }

  // Fallback to individual environment variables with test suffix
  return {
    host: process.env.POSTGRES_HOST_TEST ?? 'localhost',
    port: Number(process.env.POSTGRES_PORT_TEST ?? '5432'),
    username: process.env.POSTGRES_USER_TEST ?? 'nestuser',
    password: process.env.POSTGRES_PASSWORD_TEST ?? 'nestpassword',
    database: process.env.POSTGRES_DB_TEST ?? 'nesttracker_test',
  };
};

const environment = environmentFromString(
  process.env.NODE_ENV ?? 'development',
);
const isTestEnvironment =
  environment === Environment.Test || process.env.NODE_ENV === 'test';

export const dataSourceOptions: DataSourceOptions = {
  type: 'postgres',
  ...(isTestEnvironment
    ? getTestDatabaseConfig()
    : {
        host: process.env.POSTGRES_HOST ?? 'localhost',
        port: Number(process.env.POSTGRES_PORT ?? '5432'),
        username: process.env.POSTGRES_USER ?? 'postgres',
        password: process.env.POSTGRES_PASSWORD ?? 'postgres',
        database: process.env.POSTGRES_DB ?? 'nesttracker',
      }),
  entities: [__dirname + '/../../../**/*.entity.{ts,js}'],
  migrations: [__dirname + '/migrations/*.{ts,js}'],
  synchronize: environment !== Environment.Production && !isTestEnvironment,
  migrationsRun: isTestEnvironment,
  dropSchema: isTestEnvironment,
  logging: environment === Environment.Development,
};
