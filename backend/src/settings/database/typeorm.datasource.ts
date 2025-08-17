import 'reflect-metadata';
import { DataSource } from 'typeorm';
import { dataSourceOptions } from './data-source';

// Extend the shared options with CLI-friendly settings
export default new DataSource({
  ...dataSourceOptions,
});
