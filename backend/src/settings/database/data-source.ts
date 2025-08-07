import { DataSourceOptions } from 'typeorm';
import {
  Environment,
  environmentFromString,
} from '@backend/enums/environment/environment.enum';

const DATABASE_URL = process.env.DATABASE_URL;

export const dataSourceOptions: DataSourceOptions = {
  type: 'postgres',
  url: DATABASE_URL,
  entities: [__dirname + '/../../../**/*.entity.{ts,js}'],
  synchronize:
    environmentFromString(process.env.NODE_ENV ?? 'development') !==
    Environment.Production,
};
