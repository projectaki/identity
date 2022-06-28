import { HttpClient, HttpHeaders } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';
declare const crypto: any;

@Injectable()
export class AuthService {
  http = inject(HttpClient);

  authorize = () => {
    const state = btoa([...crypto.getRandomValues(new Int16Array(16))].reduce((a, b) => (a += b), ''));
    const authConfig = {
      state,
    };
    console.log('state', authConfig);
    sessionStorage.setItem('authConfig', JSON.stringify(authConfig));
    const responseType = 'code';
    const clientId = 'zIB73oRSqof13mYtTIud2usuxtLF7MlU';
    const redirectUrl = encodeURIComponent('http://localhost:4200/login');
    const aud = encodeURIComponent('https://identity.com');
    location.href = `https://identity-auth.eu.auth0.com/authorize?response_type=${responseType}&client_id=${clientId}&redirect_uri=${redirectUrl}&state=${state}&audience=${aud}`;
  };

  getAccessToken = () => {
    const code = JSON.parse(sessionStorage.getItem('authConfig') ?? '{}').code;
    const grantType = 'authorization_code';
    const redirectUrl = encodeURIComponent('http://localhost:4200/login');
    const clientId = 'zIB73oRSqof13mYtTIud2usuxtLF7MlU';
    const req = `grant_type=${grantType}&code=${code}&redirect_uri=${redirectUrl}&client_id=${clientId}`;
    const res = this.http.post('https://identity-auth.eu.auth0.com/oauth/token', req, {
      headers: new HttpHeaders().set('Content-Type', 'application/x-www-form-urlencoded'),
    });

    return res;
  };
}
