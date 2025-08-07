import { MigrationInterface, QueryRunner } from 'typeorm';

export class InitSchema1723060000000 implements MigrationInterface {
  name = 'InitSchema1723060000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Ensure pgcrypto is available for gen_random_uuid()
    await queryRunner.query('CREATE EXTENSION IF NOT EXISTS "pgcrypto"');

    // Create user table (reserved keyword, so quoted)
    await queryRunner.query(`
      CREATE TABLE "user" (
        "id" uuid NOT NULL DEFAULT gen_random_uuid(),
        "email" character varying NOT NULL,
        "passwordHash" text NOT NULL,
        "apiKeyHash" character varying,
        "twoFaSecret" character varying,
        "pendingTwoFaSecret" character varying,
        "twoFaLastUsed" TIMESTAMP,
        "twoFaBackupCodes" text,
        "passkeyId" character varying,
        "refreshTokenHash" text,
        "refreshTokenExpiresAt" TIMESTAMP,
        "roles" text,
        CONSTRAINT "PK_user_id" PRIMARY KEY ("id"),
        CONSTRAINT "UQ_user_email" UNIQUE ("email")
      )
    `);

    // Create api_keys table
    await queryRunner.query(`
      CREATE TABLE "api_keys" (
        "id" uuid NOT NULL DEFAULT gen_random_uuid(),
        "keyHash" character varying NOT NULL,
        "userId" uuid,
        "active" boolean NOT NULL DEFAULT true,
        "scopes" text,
        "description" character varying,
        "createdAt" TIMESTAMP NOT NULL DEFAULT now(),
        CONSTRAINT "PK_api_keys_id" PRIMARY KEY ("id"),
        CONSTRAINT "UQ_api_keys_keyHash" UNIQUE ("keyHash"),
        CONSTRAINT "FK_api_keys_user" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE NO ACTION
      )
    `);

    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS "IDX_api_keys_userId" ON "api_keys" ("userId")',
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('DROP INDEX IF EXISTS "IDX_api_keys_userId"');
    await queryRunner.query('DROP TABLE IF EXISTS "api_keys"');
    await queryRunner.query('DROP TABLE IF EXISTS "user"');
  }
}
