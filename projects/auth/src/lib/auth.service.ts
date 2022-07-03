import { Injectable } from '@angular/core';
import { AuthConfig } from '@identity-auth/models';
import { from, Subject } from 'rxjs';
import { OAuthService } from './oauth-service';

@Injectable()
export class AuthService {
  auth = new OAuthService();

  private authComplete = new Subject<boolean>();
  public authComplete$ = this.authComplete.asObservable();

  login = () => {
    this.auth.login();
  };

  setAuthConfig = (authConfig: AuthConfig) => {
    this.auth.setAuthConfig(authConfig);
  };

  handleAuthResult = () => {
    const cb = (x: boolean) => {
      if (x) {
        this.authComplete.next(true);
        this.authComplete.complete();
      }
    };
    return from(this.auth.handleAuthResult(cb));
  };

  getAccessToken = () => {
    return from(this.auth.getAccessToken());
  };
}
