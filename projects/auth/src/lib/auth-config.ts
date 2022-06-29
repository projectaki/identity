export interface AuthConfig {
  responseType: 'code';
  clientId: string;
  redirectUrl: string;
  audience: string;
  issuer: string;
  authorizeRoute: string;
  tokenRoute: string;
}
