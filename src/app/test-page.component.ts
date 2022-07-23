import { Component, inject, OnInit } from '@angular/core';
import { AuthService } from '@identity-auth/core';

@Component({
  selector: 'app-test-page',
  template: ` <button (click)="auth.login()">login</button>`,
  styles: [],
})
export class TestPageComponent implements OnInit {
  protected auth = inject(AuthService);

  constructor() {}

  ngOnInit(): void {}
}
