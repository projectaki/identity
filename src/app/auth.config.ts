import { AuthConfig } from '@identity-auth/models';

export const authConfig: AuthConfig = {
  issuer: 'https://identity-auth.eu.auth0.com',
  clientId: 'zIB73oRSqof13mYtTIud2usuxtLF7MlU',
  redirectUri: 'http://localhost:4200/login',
  postLogoutRedirectUri: window.location.origin,
  responseType: 'code',
  authorizeEndpoint: 'https://identity-auth.eu.auth0.com/authorize',
  tokenEndpoint: 'https://identity-auth.eu.auth0.com/oauth/token',
  scope: 'openid',
  endsessionEndpoint: 'https://identity-auth.eu.auth0.com/v2/logout',
  queryParams: {
    audience: 'https://identity.com',
  },
};
