import { CommonModule } from '@angular/common';
import { Component, inject, OnInit } from '@angular/core';
import { AuthService } from 'projects/auth/src/public-api';

@Component({
  selector: 'app-home',
  template: `
    <button (click)="auth.login()">authorize</button>
    <div style="overflow-wrap: break-word; max-width: 500px; padding: 1em;">{{ accessToken$ | async }}</div>
  `,
  standalone: true,
  imports: [CommonModule],
})
export class HomeComponent implements OnInit {
  protected auth = inject(AuthService);
  protected accessToken$ = this.auth.getAccessToken();

  ngOnInit(): void {}
}
