import { Route } from '@angular/router';
import { HomeComponent } from './home.component';
import { LoginComponent } from './login.component';
import { TestPageComponent } from './test-page.component';

export const routes: Route[] = [
  { path: 'home', component: HomeComponent },
  {
    path: 'login',
    component: LoginComponent,
  },
  {
    path: 'test-page',
    component: TestPageComponent,
  },
  { path: '', redirectTo: 'home', pathMatch: 'full' },
  { path: '**', redirectTo: 'home' },
];
