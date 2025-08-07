// Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character
export const PASSWORD_COMPLEXITY_REGEX =
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]).+$/;
export const API_KEY_HEADER = 'x-api-key';
export const BACKUP_CODE_COUNT = 10;
export const BACKUP_CODE_LENGTH = 8;
export const MIN_KEY_LENGTH = 32;
export const MIN_SALT_LENGTH = 16;
export const REFRESH_TOKEN_EXPIRY_DAYS = 30; // Default refresh token expiry in days
