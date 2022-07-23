import { inject, Injectable } from '@angular/core';
import { AuthResult, OIDCService, QueryParams } from '@zap.io/zap-oidc';
import { BehaviorSubject, filter, take, ReplaySubject, of, catchError, throwError } from 'rxjs';
import { AUTH_CONFIG } from './injection-tokens';

@Injectable()
export class AuthService {
  auth = new OIDCService();
  private authStateChangeCb: (authState: boolean) => void = x => {
    this.isAuthenticated.next(x);
  };

  private authResult = new BehaviorSubject<AuthResult | undefined>(undefined);
  public authResult$ = this.authResult.asObservable().pipe(
    filter(x => !!x),
    take(1)
  );

  private isAuthenticated = new ReplaySubject<boolean>(1);
  public isAuthenticated$ = this.isAuthenticated.asObservable();

  private config = inject(AUTH_CONFIG);

  constructor() {
    this.auth.setAuthStateChangeCb(this.authStateChangeCb);
  }

  login = (params?: QueryParams) => {
    this.auth.login(params);
  };

  logout = (queryParams?: QueryParams) => {
    this.auth.logout(queryParams);
  };

  localLogout = () => {
    this.auth.localLogout();
  };

  initAuth = () => {
    const cb_2 = (x: AuthResult | void) => {
      if (x) {
        this.authResult.next(x);
      }

      return x;
    };

    return this.auth.initAuth(this.config, cb_2);
  };

  getAccessToken = () => {
    return of(this.auth.getAccessToken());
  };

  getIdToken = () => {
    return of(this.auth.getIdToken()).pipe(
      catchError(() => {
        this.isAuthenticated.next(false);

        return throwError(() => 'No id token found');
      })
    );
  };

  setStorageStrategy = (strategy: Storage) => {
    this.auth.setStorageStrategy(strategy);
  };
}
