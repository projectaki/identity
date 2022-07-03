export interface AuthConfig {
  responseType: 'code';
  clientId: string;
  redirectUrl: string;
  issuer: string;
  audience?: string;
  authorizeEndpoint?: string;
  tokenEndpoint?: string;
  jwks_uri?: string;
  jwks?: any;
}

export interface AuthorizeUrlParams {
  responseType: 'code';
  clientId: string;
  redirectUrl: string;
  endPoint: string;
  audience?: string;
}

export interface DiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
}
