import * as Joi from 'joi';

export interface EnvironmentVariables {
  NODE_ENV: string;
  PORT: number;
  DATABASE_URL: string;
  DATABASE_URL_TEST?: string;
  JWT_SECRET: string;
  JWT_EXPIRATION: string;
  TWOFA_ENCRYPT_KEY: string;
  TWOFA_ENCRYPT_SALT: string;
}

export const validationSchema = Joi.object<EnvironmentVariables>({
  NODE_ENV: Joi.string()
    .valid('development', 'production', 'test')
    .default('development'),
  PORT: Joi.number().default(3000),
  DATABASE_URL: Joi.alternatives().conditional('NODE_ENV', {
    is: 'test',
    then: Joi.string().uri().optional(),
    otherwise: Joi.string().uri().required(),
  }),
  DATABASE_URL_TEST: Joi.alternatives().conditional('NODE_ENV', {
    is: 'test',
    then: Joi.string().uri().required(),
    otherwise: Joi.string().uri().optional(),
  }),
  JWT_SECRET: Joi.string().min(32).required(),
  JWT_EXPIRATION: Joi.string().default('1h'),
  TWOFA_ENCRYPT_KEY: Joi.string().min(32).required(),
  TWOFA_ENCRYPT_SALT: Joi.string().min(16).required(),
});
