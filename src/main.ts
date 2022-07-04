import { APP_INITIALIZER, enableProdMode, importProvidersFrom } from '@angular/core';
import { bootstrapApplication } from '@angular/platform-browser';
import { AppComponent } from './app/app.component';
import { HttpClientModule } from '@angular/common/http';

import { environment } from './environments/environment';
import { AuthService } from 'projects/auth/src/public-api';
import { RouterModule } from '@angular/router';
import { routes } from './app/routes';
import { loadDiscovery } from './app/auth.config';

if (environment.production) {
  enableProdMode();
}

bootstrapApplication(AppComponent, {
  providers: [
    importProvidersFrom(RouterModule.forRoot(routes)),
    importProvidersFrom(HttpClientModule),
    AuthService,
    {
      provide: APP_INITIALIZER,
      useFactory: loadDiscovery,
      deps: [AuthService],
      multi: true,
    },
  ],
}).catch(err => console.error(err));
