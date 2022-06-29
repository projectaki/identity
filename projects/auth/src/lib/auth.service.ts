import { HttpClient, HttpHeaders } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';
import { AuthConfig } from './auth-config';
declare const crypto: any;

@Injectable()
export class AuthService {
  http = inject(HttpClient);
  private authConfig!: AuthConfig;

  authorize = () => {
    const state = generateState();
    setAuthStorage('state', state);
    const { clientId, redirectUrl, responseType, audience, issuer, authorizeRoute } = this.authConfig;
    location.href = `${issuer}/${authorizeRoute}?response_type=${responseType}&client_id=${clientId}&redirect_uri=${redirectUrl}&state=${state}&audience=${audience}`;
  };

  getAccessToken = () => {
    const code = getAuthStorage().code;
    const grantType = 'authorization_code';
    const req = `grant_type=${grantType}&code=${code}&redirect_uri=${this.authConfig.redirectUrl}&client_id=${this.authConfig.clientId}`;
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
//redirect uri must be absolute, must not have a fragment
//delete code after used
export const generateState = () => btoa([...crypto.getRandomValues(new Int16Array(16))].reduce((a, b) => (a += b), ''));
export const getAuthStorage = () => JSON.parse(sessionStorage.getItem('authConfig') ?? '{}');
export const setAuthStorage = (key: string, val: any) => {
  const authConfig = getAuthStorage();
  authConfig[key] = val;
  sessionStorage.setItem('authConfig', JSON.stringify(authConfig));
};
export const removeFromAuthStorage = (key: string) => {
  const authConfig = getAuthStorage();
  delete authConfig[key];
  sessionStorage.setItem('authConfig', JSON.stringify(authConfig));
};
