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
import { setAuthStorage, getAuthStorage, removeFromAuthStorage } from '@identity-auth/storage';
import { BehaviorSubject, EMPTY, of, Subject, tap } from 'rxjs';
import { ActivatedRoute, Router } from '@angular/router';
import { DOCUMENT } from '@angular/common';

@Injectable()
export class AuthService {
  http = inject(HttpClient);
  route = inject(ActivatedRoute);
  document = inject(DOCUMENT);
  router = inject(Router);

  private authConfig!: AuthConfig;
  private authComplete = new Subject<boolean>();
  public authComplete$ = this.authComplete.asObservable();

  login = () => {
    const state = createNonce(16);
    const { codeVerifier, codeChallenge } = createCodeVerifierCodeChallengePair();
    setAuthStorage('state', state);
    setAuthStorage('codeVerifier', codeVerifier);
    const authUrl = createAuthUrl(this.authConfig, codeChallenge, state);
    location.href = authUrl;
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

  handleAuthResult = () => {
    const params = new URLSearchParams(this.document.location.search);
    this.checkState(params);
    return this.handleCodeFlowRedirect(params);
  };

  getAccessToken = () => {
    const token = getAuthStorage().authResult?.access_token;
    if (token) {
      return of(token);
    }

    return of(null);
  };

  private handleCodeFlowRedirect = (params: URLSearchParams) => {
    if (!params.has('code')) {
      this.authComplete.complete();
      this.router.navigateByUrl(this.authConfig.redirectUrl);
      return EMPTY;
    }

    const code = params.get('code')!;

    return this.fetchAccessToken(code).pipe(
      tap(data => {
        setAuthStorage('authResult', data);
        removeFromAuthStorage('codeVerifier');
        this.authComplete.next(true);
        this.authComplete.complete();
        this.router.navigateByUrl(this.authConfig.redirectUrl);
      })
    );
  };

  private fetchAccessToken = (code: string) => {
    const { codeVerifier } = getAuthStorage();
    const tokenEndpoint = createTokenUrl(this.authConfig);
    const body = createTokenRequestBody(this.authConfig, code, codeVerifier);
    const res = this.http.post(tokenEndpoint, body, {
      headers: new HttpHeaders().set('Content-Type', 'application/x-www-form-urlencoded'),
    });

    return res;
  };

  private checkState = (params: URLSearchParams) => {
    const state = params.get('state');
    const authStorage = getAuthStorage();
    if (authStorage.state && !state) throw new Error('Missing state parameter from redirect');
    if (!authStorage.state && state) throw new Error('Missing state in storage but expected one');
    if (authStorage.state && authStorage.state !== state) throw new Error('Invalid state');
    if (authStorage.state && state) removeFromAuthStorage('state');
  };
}
