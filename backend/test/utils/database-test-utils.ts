import { DataSource } from 'typeorm';
import { dataSourceOptions } from '@backend/settings/database/data-source';
import { UserSeeder } from '@backend/database/seeds/user.seed';
import { ApiKeySeeder } from '@backend/database/seeds/api-key.seed';

export class DatabaseTestUtils {
  private static dataSource: DataSource;

  /**
   * Initialize test database connection
   */
  static async initializeTestDatabase(): Promise<DataSource> {
    if (this.dataSource?.isInitialized) {
      return this.dataSource;
    }

    this.dataSource = new DataSource(dataSourceOptions);
    await this.dataSource.initialize();

    // Run migrations to ensure schema is up to date
    await this.dataSource.runMigrations();

    return this.dataSource;
  }

  /**
   * Clean and seed test database with fresh data
   */
  static async seedTestDatabase(): Promise<void> {
    if (!this.dataSource?.isInitialized) {
      throw new Error(
        'Database not initialized. Call initializeTestDatabase first.',
      );
    }

    // Clear all data first
    await this.clearAllTables();

    // Run seeders
    const userSeeder = new UserSeeder();
    await userSeeder.run(this.dataSource);

    const apiKeySeeder = new ApiKeySeeder();
    await apiKeySeeder.run(this.dataSource);
  }

  /**
   * Clear all tables for clean test state
   */
  static async clearAllTables(): Promise<void> {
    if (!this.dataSource?.isInitialized) {
      return;
    }

    // Get all table names
    const entities = this.dataSource.entityMetadatas;

    // Disable foreign key checks temporarily
    await this.dataSource.query('SET FOREIGN_KEY_CHECKS = 0');

    // Clear all tables
    for (const entity of entities) {
      await this.dataSource.query(`DELETE FROM ${entity.tableName}`);
    }

    // Re-enable foreign key checks
    await this.dataSource.query('SET FOREIGN_KEY_CHECKS = 1');
  }

  /**
   * Close test database connection
   */
  static async closeTestDatabase(): Promise<void> {
    if (this.dataSource?.isInitialized) {
      await this.dataSource.destroy();
    }
  }

  /**
   * Get test database connection
   */
  static getTestDataSource(): DataSource {
    if (!this.dataSource?.isInitialized) {
      throw new Error(
        'Database not initialized. Call initializeTestDatabase first.',
      );
    }
    return this.dataSource;
  }

  /**
   * Reset database to initial state (drop schema and run migrations)
   */
  static async resetTestDatabase(): Promise<void> {
    if (!this.dataSource?.isInitialized) {
      throw new Error(
        'Database not initialized. Call initializeTestDatabase first.',
      );
    }

    // Drop all tables and recreate schema
    await this.dataSource.dropDatabase();
    await this.dataSource.runMigrations();
  }

  /**
   * Get repository for testing
   */
  static getRepository<T>(entity: new () => T) {
    return this.getTestDataSource().getRepository(entity);
  }
}
