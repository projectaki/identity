import { AuthService } from '@identity-auth/core';
import { AuthConfig } from '@identity-auth/models';
import { lastValueFrom } from 'rxjs';

const AUTH_CONFIG: AuthConfig = {
  issuer: 'https://identity-auth.eu.auth0.com',
  clientId: 'zIB73oRSqof13mYtTIud2usuxtLF7MlU',
  redirectUrl: 'http://localhost:4200/login',
  audience: 'https://identity.com',
  responseType: 'code',
  authorizeEndpoint: 'https://identity-auth.eu.auth0.com/authorize',
  tokenEndpoint: 'https://identity-auth.eu.auth0.com/oauth/token',
  jwks_uri: 'https://identity-auth.eu.auth0.com/.well-known/jwks.json',
};

export function loadDiscovery(auth: AuthService) {
  auth.setAuthConfig(AUTH_CONFIG);
  return () => lastValueFrom(auth.loadDiscoveryDocument());
}
