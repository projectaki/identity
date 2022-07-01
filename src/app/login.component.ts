import { Component, inject, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { getAuthStorage, setAuthStorage, removeFromAuthStorage } from 'projects/auth/src/lib/helpers';
import { AuthService } from 'projects/auth/src/public-api';
import { switchMap, tap } from 'rxjs/operators';

@Component({
  selector: 'app-login',
  template: ` Login page `,
  standalone: true,
})
export class LoginComponent implements OnInit {
  route = inject(ActivatedRoute);
  protected auth = inject(AuthService);
  private router = inject(Router);

  ngOnInit(): void {
    this.route.queryParams
      .pipe(
        switchMap(({ code, state }) => {
          const authStorage = getAuthStorage();
          if (authStorage.state !== state) throw new Error('Invalid state');
          setAuthStorage('code', code);

          return this.auth.getAccessToken().pipe(
            tap(authResult => {
              setAuthStorage('authResult', authResult);
              removeFromAuthStorage('code');
              removeFromAuthStorage('codeVerifier');
              removeFromAuthStorage('state');
            })
          );
        })
      )
      .subscribe(() => (location.href = 'http://localhost:4200/home'));
  }
}
