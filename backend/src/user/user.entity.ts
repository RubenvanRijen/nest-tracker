export class User {
  id: string;
  email: string;
  passwordHash: string;
  apiKeyHash?: string;
  twoFaSecret?: string;
  passkeyId?: string;
  roles?: string[];
}
