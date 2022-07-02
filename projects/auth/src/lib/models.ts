export interface AuthConfig {
  responseType: 'code';
  clientId: string;
  redirectUrl: string;
  issuer: string;
  useDiscovery: boolean;
  audience?: string;
  authorizeEndpoint?: string;
  tokenEndpoint?: string;
}

export interface AuthorizeUrlParams {
  responseType: 'code';
  clientId: string;
  redirectUrl: string;
  endPoint: string;
  audience?: string;
}
