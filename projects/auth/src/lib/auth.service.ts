import { HttpClient, HttpHeaders } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';
import { AuthConfig } from '@identity-auth/models';
import {
  createAuthUrl,
  createCodeVerifierCodeChallengePair,
  createNonce,
  createTokenRequestBody,
  createTokenUrl,
} from '@identity-auth/core';
import { setAuthStorage, getAuthStorage } from '@identity-auth/storage';

@Injectable()
export class AuthService {
  http = inject(HttpClient);
  private authConfig!: AuthConfig;

  authorize = () => {
    const state = createNonce(16);
    const { codeVerifier, codeChallenge } = createCodeVerifierCodeChallengePair();
    setAuthStorage('state', state);
    setAuthStorage('codeVerifier', codeVerifier);
    const authUrl = createAuthUrl(this.authConfig, codeChallenge, state);
    location.href = authUrl;
  };

  getAccessToken = () => {
    const { code, codeVerifier } = getAuthStorage();
    const tokenEndpoint = createTokenUrl(this.authConfig);
    const body = createTokenRequestBody(this.authConfig, code, codeVerifier);
    const res = this.http.post(tokenEndpoint, body, {
      headers: new HttpHeaders().set('Content-Type', 'application/x-www-form-urlencoded'),
    });
    return res;
  };

  setAuthConfig = (authConfig: AuthConfig) => {
    const redirectUrl = encodeURIComponent(authConfig.redirectUrl);
    const aud = authConfig.audience ? encodeURIComponent(authConfig.audience) : '';

    this.authConfig = {
      ...authConfig,
      redirectUrl,
    };

    if (aud) {
      this.authConfig.audience = aud;
    }
  };
}
