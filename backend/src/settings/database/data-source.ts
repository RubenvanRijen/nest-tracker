import { Environment } from '@backend/enums/environment/environment.enum';
import { DataSourceOptions } from 'typeorm';

const NODE_ENV = process.env.NODE_ENV ?? 'development';
const isTest = NODE_ENV?.toLowerCase() === Environment.Test.toLowerCase();

const DATABASE_URL = isTest
  ? (process.env.DATABASE_URL_TEST ?? process.env.DATABASE_URL)
  : process.env.DATABASE_URL;

export const dataSourceOptions: DataSourceOptions = {
  type: 'postgres',
  url: DATABASE_URL,
  entities: [`${__dirname}/../entities/**/*{.ts,.js}`],
  migrations: [`${__dirname}/../migrations/*{.ts,.js}`],
  synchronize: false,
  dropSchema: false,
  logging: NODE_ENV === Environment.Development.toLowerCase(),
};
