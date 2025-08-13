import { MigrationInterface, QueryRunner } from 'typeorm';

export class InitialSchema1704802320000 implements MigrationInterface {
  name = 'InitialSchema1704802320000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Create user table
    await queryRunner.query(`
      CREATE TABLE "user" (
        "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
        "email" character varying NOT NULL,
        "passwordHash" character varying NOT NULL,
        "apiKeyHash" character varying,
        "twoFaSecret" character varying,
        "pendingTwoFaSecret" character varying,
        "twoFaLastUsed" TIMESTAMP,
        "twoFaBackupCodes" text,
        "passkeyId" character varying,
        "refreshTokenHash" text,
        "refreshTokenExpiresAt" TIMESTAMP,
        "roles" text,
        CONSTRAINT "UQ_user_email" UNIQUE ("email"),
        CONSTRAINT "PK_user_id" PRIMARY KEY ("id")
      )
    `);

    // Create api_keys table
    await queryRunner.query(`
      CREATE TABLE "api_keys" (
        "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
        "keyHash" character varying NOT NULL,
        "active" boolean NOT NULL DEFAULT true,
        "scopes" text,
        "description" character varying,
        "createdAt" TIMESTAMP NOT NULL DEFAULT now(),
        "userId" uuid,
        CONSTRAINT "UQ_api_keys_keyHash" UNIQUE ("keyHash"),
        CONSTRAINT "PK_api_keys_id" PRIMARY KEY ("id")
      )
    `);

    // Create foreign key constraint
    await queryRunner.query(`
      ALTER TABLE "api_keys" 
      ADD CONSTRAINT "FK_api_keys_userId" 
      FOREIGN KEY ("userId") 
      REFERENCES "user"("id") 
      ON DELETE CASCADE 
      ON UPDATE NO ACTION
    `);

    // Create indexes for performance
    await queryRunner.query(
      `CREATE INDEX "IDX_user_email" ON "user" ("email")`,
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_api_keys_userId" ON "api_keys" ("userId")`,
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_api_keys_active" ON "api_keys" ("active")`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Drop indexes
    await queryRunner.query(`DROP INDEX "IDX_api_keys_active"`);
    await queryRunner.query(`DROP INDEX "IDX_api_keys_userId"`);
    await queryRunner.query(`DROP INDEX "IDX_user_email"`);

    // Drop foreign key constraint
    await queryRunner.query(
      `ALTER TABLE "api_keys" DROP CONSTRAINT "FK_api_keys_userId"`,
    );

    // Drop tables
    await queryRunner.query(`DROP TABLE "api_keys"`);
    await queryRunner.query(`DROP TABLE "user"`);
  }
}
