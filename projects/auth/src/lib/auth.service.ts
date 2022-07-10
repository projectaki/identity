import { Injectable } from '@angular/core';
import { AuthConfig } from '@identity-auth/models';
import { BehaviorSubject, from, Subject } from 'rxjs';
import { OAuthService } from './oauth-service';

@Injectable()
export class AuthService {
  auth = new OAuthService();

  private authComplete = new Subject<boolean>();
  public authComplete$ = this.authComplete.asObservable();

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
    const cb = (x: boolean) => {
      if (x) {
        this.authComplete.next(true);
        this.authComplete.complete();

        this.isAuthenticated.next(true);
      }
    };
    return from(this.auth.handleAuthResult(cb));
  };

  getAccessToken = () => {
    return from(this.auth.getAccessToken());
  };

  getIdToken = () => {
    const cb = (x: boolean) => {
      if (x) {
        this.isAuthenticated.next(true);
      } else {
        this.isAuthenticated.next(false);
      }
    };
    return from(this.auth.getIdToken(cb));
  };

  loadDiscoveryDocument = () => {
    return from(this.auth.loadDiscoveryDocument());
  };
}
