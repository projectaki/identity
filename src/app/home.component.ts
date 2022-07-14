import { CommonModule } from '@angular/common';
import { Component, inject, OnInit } from '@angular/core';
import { base64Decode } from '@identity-auth/encoding';
import { IdToken } from '@identity-auth/models';
import { AUTH_CONFIG } from 'projects/auth/src/lib/injection-tokens';
import { AuthService } from 'projects/auth/src/public-api';
import { map } from 'rxjs';

@Component({
  selector: 'app-home',
  template: `
    <ng-container *ngIf="auth.isAuthenticated$ | async as authed; else loggedOut">
      <button (click)="logout()">Log out</button>
    </ng-container>
    <ng-template #loggedOut>
      <button (click)="auth.login()">authorize</button>
      <ng-container *ngIf="idTokenString$ | async as idtokenstring">
        <button (click)="validate(idtokenstring)">validate</button>
      </ng-container>
    </ng-template>

    <ng-container *ngIf="idToken$ | async as idtoken">
      <h2>Id token</h2>
      <pre>{{ idtoken.header | json }}</pre>
      <pre>{{ idtoken.body | json }}</pre>
    </ng-container>
    <ng-container *ngIf="accessToken$ | async as accesstoken">
      <h2>Access token</h2>
      <pre>{{ accesstoken.header | json }}</pre>
      <pre>{{ accesstoken.body | json }}</pre>
    </ng-container>
  `,
  standalone: true,
  imports: [CommonModule],
})
export class HomeComponent implements OnInit {
  protected auth = inject(AuthService);
  authConfig = inject(AUTH_CONFIG);
  protected accessToken$ = this.auth.getAccessToken().pipe(
    map(t => {
      if (!t) return null;
      const [header, body, signature] = t.split('.');

      const decodedHeader = base64Decode(header);
      const decodedBody = base64Decode(body);

      return { header: JSON.parse(decodedHeader), body: JSON.parse(decodedBody) };
    })
  );
  protected idTokenString$ = this.auth.getIdToken();
  protected idToken$ = this.auth.getIdToken().pipe(
    map(t => {
      if (!t) return null;
      const [header, body, signature] = t.split('.');

      const decodedHeader = base64Decode(header);
      const decodedBody = base64Decode(body);

      return { header: JSON.parse(decodedHeader), body: JSON.parse(decodedBody) };
    })
  );

  ngOnInit(): void {}

  validate(token: string) {
    this.auth.auth.validate(token);
  }

  logout() {
    this.auth.localLogout();
    return;
    this.auth.logout({
      returnTo: this.authConfig.postLogoutRedirectUri,
      client_id: this.authConfig.clientId,
    });
  }
}
