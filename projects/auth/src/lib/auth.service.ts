import { inject, Injectable } from '@angular/core';
import { AuthConfig, AuthResult } from '@identity-auth/models';
import { BehaviorSubject, catchError, filter, from, Observable, of, Subject, tap, throwError } from 'rxjs';
import { AUTH_CONFIG } from './injection-tokens';
import { OAuthService } from './oauth-service';

@Injectable()
export class AuthService {
  auth = new OAuthService();

  private authComplete = new BehaviorSubject<boolean>(false);
  public authComplete$ = this.authComplete.asObservable().pipe(filter(x => x));

  private isAuthenticated = new BehaviorSubject<boolean>(false);
  public isAuthenticated$ = this.isAuthenticated.asObservable();

  private config = inject(AUTH_CONFIG);

  login = () => {
    this.auth.login();
  };

  logout = () => {
    const cb = () => this.isAuthenticated.next(false);
    this.auth.logout(cb);
  };

  localLogout = () => {
    const cb = () => this.isAuthenticated.next(false);
    this.auth.localLogout(cb);
  };

  initAuth = () => {
    const cb_1 = (x: boolean) => this.isAuthenticated.next(x);
    const cb_2 = (x: AuthResult | void) => {
      if (x) {
        this.authComplete.next(true);
        this.authComplete.complete();
      }
      return x;
    };
    return this.auth.initAuth(this.config, cb_1, cb_2);
  };

  getAccessToken = () => {
    return of(this.auth.getAccessToken());
  };

  getIdToken = () => {
    const cb = (x: string) => {
      console.log('id token', x);
    };
    return of(this.auth.getIdToken(cb)).pipe(
      catchError(() => {
        this.isAuthenticated.next(false);

        return throwError(() => 'No id token found');
      })
    );
  };

  invokeAfterAuthHandled = (action: () => void) => {
    this.auth.invokeAfterAuthHandled(action);
  };
}
