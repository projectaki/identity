import { APP_INITIALIZER, enableProdMode, importProvidersFrom } from '@angular/core';
import { bootstrapApplication } from '@angular/platform-browser';
import { AppComponent } from './app/app.component';
import { HttpClientModule } from '@angular/common/http';

import { environment } from './environments/environment';
import { AuthService } from 'projects/auth/src/public-api';
import { RouterModule } from '@angular/router';
import { routes } from './app/routes';
import { AUTH_CONFIG } from 'projects/auth/src/lib/injection-tokens';
import { authConfig } from './app/auth.config';

if (environment.production) {
  enableProdMode();
}

bootstrapApplication(AppComponent, {
  providers: [
    importProvidersFrom(RouterModule.forRoot(routes)),
    importProvidersFrom(HttpClientModule),
    AuthService,
    {
      provide: AUTH_CONFIG,
      useValue: authConfig,
    },
    {
      provide: APP_INITIALIZER,
      useFactory: (auth: AuthService) => () => auth.initAuth(),
      deps: [AuthService],
      multi: true,
    },
  ],
}).catch(err => console.error(err));
