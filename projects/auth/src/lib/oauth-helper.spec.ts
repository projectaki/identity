import { query } from '@angular/animations';
import { createAuthUrl } from './oauth-helper';

describe('oauth-helper', () => {
  describe('createAuthUrl', () => {
    it('should create auth url with all params present', () => {
      const authUrl = createAuthUrl(
        'https://identity-auth.eu.auth0.com/authorize',
        {
          client_id: 'cid',
          redirect_uri: 'red',
          response_type: 'code',
          scope: 'openid',
          state: 'st',
          response_mode: 'query',
          nonce: 'non',
          display: 'popup',
          prompt: 'none',
          max_age: 10,
          ui_locales: 'loc',
          id_token_hint: 'id',
          login_hint: 'login',
          acr_values: 'acr',
          extra_param: 'extra',
        },
        'codeChallenge'
      );
      expect(authUrl).toEqual(
        `https://identity-auth.eu.auth0.com/authorize?client_id=cid&redirect_uri=red&response_type=code&scope=openid&state=st&response_mode=query&nonce=non&display=popup&prompt=none&max_age=10&ui_locales=loc&id_token_hint=id&login_hint=login&acr_values=acr&extra_param=extra&code_challenge=codeChallenge&code_challenge_method=S256`
      );
    });

    it('should create auth url with state, codeChallenge and other extra params missing', () => {
      const authUrl = createAuthUrl('https://identity-auth.eu.auth0.com/authorize', {
        client_id: 'cid',
        redirect_uri: 'red',
        response_type: 'code',
        scope: 'openid',
        state: 'st',
      });
      expect(authUrl).toEqual(
        `https://identity-auth.eu.auth0.com/authorize?client_id=cid&redirect_uri=red&response_type=code&scope=openid&state=st`
      );
    });
  });
});
