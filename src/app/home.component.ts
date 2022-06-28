import { Component, inject, OnInit } from '@angular/core';
import { AuthService } from 'projects/auth/src/public-api';

@Component({
  selector: 'app-home',
  template: ` <button (click)="auth.authorize()">authorize</button> `,
  standalone: true,
})
export class HomeComponent implements OnInit {
  protected auth = inject(AuthService);

  ngOnInit(): void {}
}
