// Minimal ambient types to satisfy the TypeScript checker in this workspace.
declare module 'jose' {
  export class SignJWT {
    constructor(payload: any);
    setProtectedHeader(header: Record<string, any>): SignJWT;
    setExpirationTime(exp: string): SignJWT;
    sign(key: Uint8Array | CryptoKey | string): Promise<string>;
  }

  export function jwtVerify(token: string, key: Uint8Array | CryptoKey | string): Promise<{ payload: any }>;
}

// Minimal D1Database shape used by the project (Cloudflare D1-like)
interface D1Database {
  prepare(query: string): {
    bind(...args: any[]): {
      first(): Promise<any>;
      all(): Promise<{ results: any[] }>;
      run(): Promise<any>;
    };
  };
}

export {};
