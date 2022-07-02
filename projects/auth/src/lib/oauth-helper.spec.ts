import { createAuthUrl } from './oauth-helper';

describe('oauth-helper', () => {
  describe('createAuthUrl', () => {
    it('should create auth url with all params present', () => {
      const authUrl = createAuthUrl(
        {
          audience: 'aud',
          clientId: 'cid',
          redirectUrl: 'red',
          responseType: 'code',
          issuer: 'https://identity-auth.eu.auth0.com',
          useDiscovery: false,
          authorizeEndpoint: 'https://identity-auth.eu.auth0.com/authorize',
          tokenEndpoint: 'https://identity-auth.eu.auth0.com/oauth/token',
        },
        'codeChallenge',
        'state'
      );
      expect(authUrl).toEqual(
        'https://identity-auth.eu.auth0.com/authorize?response_type=code&client_id=cid&redirect_uri=red&state=state&audience=aud&code_challenge=codeChallenge&code_challenge_method=S256'
      );
    });

    it('should create auth url with state, codeChallenge and audience missing', () => {
      const authUrl = createAuthUrl({
        clientId: 'cid',
        redirectUrl: 'red',
        responseType: 'code',
        issuer: 'https://identity-auth.eu.auth0.com',
        useDiscovery: false,
        authorizeEndpoint: 'https://identity-auth.eu.auth0.com/authorize',
        tokenEndpoint: 'https://identity-auth.eu.auth0.com/oauth/token',
      });
      expect(authUrl).toEqual(
        'https://identity-auth.eu.auth0.com/authorize?response_type=code&client_id=cid&redirect_uri=red'
      );
    });
  });
});
