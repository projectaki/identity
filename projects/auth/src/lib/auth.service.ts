import { HttpClient, HttpHeaders } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';
import { AuthConfig } from './auth-config';
import { createCodeVerifier, createCodeChallenge, getAuthStorage, setAuthStorage } from './helpers';

@Injectable()
export class AuthService {
  http = inject(HttpClient);
  private authConfig!: AuthConfig;

  authorize = () => {
    const state = createCodeVerifier();
    const codeVerifier = createCodeVerifier();
    console.log('CV', codeVerifier);
    const codeChallenge = createCodeChallenge(codeVerifier);
    setAuthStorage('state', state);
    setAuthStorage('codeVerifier', codeVerifier);
    const { clientId, redirectUrl, responseType, audience, issuer, authorizeRoute } = this.authConfig;
    location.href = `${issuer}/${authorizeRoute}?response_type=${responseType}&client_id=${clientId}&redirect_uri=${redirectUrl}&state=${state}&audience=${audience}&code_challenge=${codeChallenge}&code_challenge_method=S256`;
  };

  getAccessToken = () => {
    const authStorage = getAuthStorage();
    const { code, codeVerifier } = authStorage;
    const grantType = 'authorization_code';
    const req = `grant_type=${grantType}&code=${code}&redirect_uri=${this.authConfig.redirectUrl}&client_id=${this.authConfig.clientId}&code_verifier=${codeVerifier}`;
    const res = this.http.post('https://identity-auth.eu.auth0.com/oauth/token', req, {
      headers: new HttpHeaders().set('Content-Type', 'application/x-www-form-urlencoded'),
    });

    return res;
  };

  setAuthConfig = (authConfig: AuthConfig) => {
    const redirectUrl = encodeURIComponent(authConfig.redirectUrl);
    const aud = encodeURIComponent(authConfig.audience);

    this.authConfig = {
      ...authConfig,
      redirectUrl,
      audience: aud,
    };
  };
}
