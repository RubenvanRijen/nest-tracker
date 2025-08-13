import * as dotenv from 'dotenv';
import { DataSource } from 'typeorm';
import { dataSourceOptions } from '@backend/settings/database/data-source';
import { UserSeeder } from './user.seed';
import { ApiKeySeeder } from './api-key.seed';

// Load test environment variables
dotenv.config({ path: '../../../.env.testing' });

async function runSeeders() {
  console.log('🌱 Starting database seeding...');

  // Create data source for seeding
  const dataSource = new DataSource(dataSourceOptions);

  try {
    // Initialize connection
    await dataSource.initialize();
    console.log('📦 Database connection established');

    // Run seeders in order
    const userSeeder = new UserSeeder();
    await userSeeder.run(dataSource);

    const apiKeySeeder = new ApiKeySeeder();
    await apiKeySeeder.run(dataSource);

    console.log('🎉 Database seeding completed successfully!');
  } catch (error) {
    console.error('❌ Error during seeding:', error);
    process.exit(1);
  } finally {
    // Close connection
    if (dataSource.isInitialized) {
      await dataSource.destroy();
      console.log('🔌 Database connection closed');
    }
  }
}

// Run seeders if this script is executed directly
if (require.main === module) {
  runSeeders()
    .then(() => {
      console.log('✅ Seeding process finished');
      process.exit(0);
    })
    .catch((error) => {
      console.error('💥 Seeding process failed:', error);
      process.exit(1);
    });
}
