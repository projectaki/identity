import { Component, inject, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from 'projects/auth/src/public-api';

@Component({
  selector: 'app-login',
  template: ` Login page `,
  standalone: true,
})
export class LoginComponent implements OnInit {
  protected auth = inject(AuthService);
  private router = inject(Router);

  ngOnInit(): void {
    this.auth.handleAuthResult().subscribe(x => {
      console.log('handled auth result', x);
      this.router.navigate(['/']);
    });
  }
}
