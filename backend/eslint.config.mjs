// @ts-check

// This is a unified ESLint configuration for your Nest.js backend.
// It uses the new flat config format and combines the best rules from your
// previous files while fixing some minor issues.

import js from '@eslint/js';
import eslintPluginPrettierRecommended from 'eslint-plugin-prettier/recommended';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  // Ignore the configuration file itself to prevent it from being linted.
  {
    ignores: ['eslint.config.mjs', 'dist'],
  },
  // Apply ESLint's recommended rules
  js.configs.recommended,
  // Apply TypeScript ESLint's recommended rules with type checking
  ...tseslint.configs.recommendedTypeChecked,
  // Use Prettier's recommended configuration to disable conflicting ESLint rules
  eslintPluginPrettierRecommended,
  {
    files: ['**/*.ts'],
    languageOptions: {
      globals: {
        ...globals.node,
        ...globals.jest,
      },
      sourceType: 'commonjs',
      parserOptions: {
        // This enables the TypeScript language service for type-aware rules.
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    // This setting is for the import resolver plugin, which helps with module resolution.
    settings: {
      'import/resolver': {
        typescript: {
          alwaysTryTypes: true,
          project: ['./tsconfig.json', './tsconfig.build.json'],
        },
      },
    },
    // Custom rules and overrides for your project.
    rules: {
      // Re-enable some warnings that were turned off in the base configs.
      '@typescript-eslint/no-explicit-any': 'off', // A common practice to allow "any" for flexibility
      '@typescript-eslint/no-floating-promises': 'warn',
      '@typescript-eslint/no-unsafe-argument': 'warn',
      '@typescript-eslint/no-unused-vars': [
        'warn',
        { argsIgnorePattern: '^_' },
      ],
      // Recommended Nest.js specific rules
      'no-console': ['warn', { allow: ['warn', 'error'] }],
      semi: ['error', 'always'],
      quotes: ['error', 'single'],
      // The `trailingComma` rule is handled by Prettier.
    },
  },
);
