import { DataSourceOptions } from 'typeorm';
import {
  Environment,
  environmentFromString,
} from '@backend/enums/environment/environment.enum';

const DATABASE_URL = process.env.DATABASE_URL;

export const dataSourceOptions: DataSourceOptions = {
  type: 'postgres',
  url: DATABASE_URL,
  host: DATABASE_URL ? undefined : (process.env.POSTGRES_HOST ?? 'localhost'),
  port: DATABASE_URL ? undefined : Number(process.env.POSTGRES_PORT ?? '5432'),
  username: DATABASE_URL
    ? undefined
    : (process.env.POSTGRES_USER ?? 'postgres'),
  password: DATABASE_URL
    ? undefined
    : (process.env.POSTGRES_PASSWORD ?? 'postgres'),
  database: DATABASE_URL
    ? undefined
    : (process.env.POSTGRES_DB ?? 'nesttracker'),
  entities: [__dirname + '/../../../**/*.entity.{ts,js}'],
  synchronize:
    environmentFromString(process.env.NODE_ENV ?? 'development') !==
    Environment.Production,
};
