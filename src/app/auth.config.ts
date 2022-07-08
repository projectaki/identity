import { AuthService } from '@identity-auth/core';
import { AuthConfig } from '@identity-auth/models';
import { lastValueFrom } from 'rxjs';

const AUTH_CONFIG: AuthConfig = {
  issuer: 'https://identity-auth.eu.auth0.com',
  clientId: 'zIB73oRSqof13mYtTIud2usuxtLF7MlU',
  redirectUri: 'http://localhost:4200/login',
  responseType: 'code',
  authorizeEndpoint: 'https://identity-auth.eu.auth0.com/authorize',
  tokenEndpoint: 'https://identity-auth.eu.auth0.com/oauth/token',
  scope: 'openid',
  queryParams: {
    audience: 'https://identity.com',
  },
};

export function loadDiscovery(auth: AuthService) {
  auth.setAuthConfig(AUTH_CONFIG);
  return () => lastValueFrom(auth.loadDiscoveryDocument());
}
