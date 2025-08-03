import { InternalServerErrorException } from '@nestjs/common';

/**
 * Application environment types for configuration and runtime checks.
 */

export enum Environment {
  Production = 'production',
  Development = 'development',
  Test = 'test',
}

/**
 * Converts a string to the corresponding Environment enum value.
 * Throws an error if the string does not match any known environment.
 *
 * @param str - The environment string to convert.
 * @returns The corresponding Environment enum value.
 * @throws InternalServerErrorException if the string is invalid.
 */
export function environmentFromString(str: string): Environment {
  switch (str?.toLowerCase()) {
    case 'production':
      return Environment.Production;
    case 'test':
      return Environment.Test;
    case 'development':
      return Environment.Development;
    default:
      throw new InternalServerErrorException(
        `Invalid NODE_ENV value: '${str}'. Must be one of: production, development, test.`,
      );
  }
}
