import { inject, Injectable } from '@angular/core';
import { AuthConfig, AuthResult, QueryParams } from '@identity-auth/models';
import {
  BehaviorSubject,
  catchError,
  filter,
  from,
  Observable,
  of,
  ReplaySubject,
  Subject,
  take,
  tap,
  throwError,
} from 'rxjs';
import { AUTH_CONFIG } from './injection-tokens';
import { OIDCService } from './oidc-service';

@Injectable()
export class AuthService {
  auth = new OIDCService();

  private authResult = new BehaviorSubject<AuthResult | undefined>(undefined);
  public authResult$ = this.authResult.asObservable().pipe(
    filter(x => !!x),
    take(1)
  );

  private isAuthenticated = new ReplaySubject<boolean>(1);
  public isAuthenticated$ = this.isAuthenticated.asObservable();

  private redirectPageProcessedAndLoaded = new BehaviorSubject<boolean>(false);
  public redirectPageProcessedAndLoaded$ = this.redirectPageProcessedAndLoaded.asObservable().pipe(
    filter(x => x),
    take(1)
  );

  private config = inject(AUTH_CONFIG);

  login = () => {
    this.auth.login();
  };

  logout = (queryParams?: QueryParams) => {
    const cb = () => this.isAuthenticated.next(false);
    this.auth.logout(queryParams, cb);
  };

  localLogout = () => {
    const cb = () => this.isAuthenticated.next(false);
    this.auth.localLogout(cb);
  };

  initAuth = () => {
    const cb_1 = (x: boolean) => this.isAuthenticated.next(!!x);
    const cb_2 = (x: AuthResult | void) => {
      if (x) {
        this.authResult.next(x);
      } else {
        this.redirectPageProcessedAndLoaded.next(true);
      }

      return x;
    };

    return this.auth.initAuth(this.config, cb_1, cb_2);
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

  invokeAfterAuthHandled = (action: () => void) => {
    this.auth.invokeAfterAuthHandled(action);
  };
}
