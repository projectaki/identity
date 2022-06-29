import { Component, inject } from '@angular/core';
import { RouterModule } from '@angular/router';
import { AuthService } from 'projects/auth/src/public-api';

@Component({
  selector: 'app-root',
  imports: [RouterModule],
  template: `<router-outlet></router-outlet>`,
  standalone: true,
})
export class AppComponent {
  protected auth = inject(AuthService);

  ngOnInit(): void {
    this.auth.setAuthConfig({
      audience: 'https://identity.com',
      clientId: 'zIB73oRSqof13mYtTIud2usuxtLF7MlU',
      redirectUrl: 'http://localhost:4200/login',
      responseType: 'code',
      issuer: 'https://identity-auth.eu.auth0.com',
      authorizeRoute: 'authorize',
      tokenRoute: 'oauth/token',
    });
  }
}
