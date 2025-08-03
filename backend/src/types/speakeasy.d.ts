declare module 'speakeasy' {
  export interface GeneratedSecret {
    ascii: string;
    hex: string;
    base32: string;
    otpauth_url: string;
  }

  export function generateSecret(options?: {
    length?: number;
    name?: string;
    issuer?: string;
  }): GeneratedSecret;

  export namespace totp {
    export function verify(options: {
      secret: string;
      encoding: 'base32' | 'ascii' | 'hex';
      token: string;
      window?: number;
    }): boolean;
  }

  const _default: {
    generateSecret: typeof generateSecret;
    totp: typeof totp;
  };
  export default _default;
}
