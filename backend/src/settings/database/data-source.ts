import { DataSourceOptions } from 'typeorm';
import {
  Environment,
  environmentFromString,
} from '@backend/enums/environment/environment.enum';

export const dataSourceOptions: DataSourceOptions = {
  type: 'postgres',
  host: process.env.POSTGRES_HOST ?? 'localhost',
  port: Number(process.env.POSTGRES_PORT ?? '5432'),
  username: process.env.POSTGRES_USER ?? 'postgres',
  password: process.env.POSTGRES_PASSWORD ?? 'postgres',
  database: process.env.POSTGRES_DB ?? 'nesttracker',
  entities: [__dirname + '/../../../**/*.entity.{ts,js}'],
  synchronize:
    environmentFromString(process.env.NODE_ENV ?? 'development') !==
    Environment.Production,
};
