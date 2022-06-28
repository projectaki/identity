import { Component, inject, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
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

  ngOnInit(): void {
    this.route.queryParams
      .pipe(
        switchMap(({ code, state }) => {
          const authConfig = JSON.parse(sessionStorage.getItem('authConfig') ?? '{}');
          if (authConfig.state !== state) throw new Error('Invalid state');
          sessionStorage.setItem('authConfig', JSON.stringify({ ...authConfig, code }));

          return this.auth.getAccessToken().pipe(
            tap(token => {
              const authConfig = JSON.parse(sessionStorage.getItem('authConfig') ?? '{}');
              sessionStorage.setItem('authConfig', JSON.stringify({ ...authConfig, token }));
            })
          );
        })
      )
      .subscribe();
  }
}
