import { Injectable } from '@angular/core';
import { AuthConfig, AuthResult } from '@identity-auth/models';
import { BehaviorSubject, catchError, filter, from, Observable, of, Subject, tap, throwError } from 'rxjs';
import { OAuthService } from './oauth-service';

@Injectable()
export class AuthService {
  auth = new OAuthService();

  private authComplete = new BehaviorSubject<boolean>(false);
  public authComplete$ = this.authComplete.asObservable().pipe(filter(x => x));

  private isAuthenticated = new BehaviorSubject<boolean>(false);
  public isAuthenticated$ = this.isAuthenticated.asObservable();

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

  setAuthConfig = (authConfig: AuthConfig) => {
    this.auth.setAuthConfig(authConfig);
  };

  handleAuthResult = () => {
    const cb = (x: AuthResult | void) => {
      if (x) {
        this.authComplete.next(true);
        this.authComplete.complete();
      }
      return x;
    };

    return from(this.auth.handleAuthResult(cb)).pipe(
      filter(x => !!x),
      tap(x => this.isAuthenticated.next(true))
    );
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

  loadDiscoveryDocument = () => {
    return from(this.auth.loadDiscoveryDocument());
  };
}
