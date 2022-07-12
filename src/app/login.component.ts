import { Component, inject, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { AuthService } from 'projects/auth/src/public-api';

@Component({
  selector: 'app-login',
  template: ` Login page `,
  standalone: true,
})
export class LoginComponent implements OnInit {
  protected auth = inject(AuthService);
  private route = inject(ActivatedRoute);
  private router = inject(Router);

  ngOnInit(): void {
    this.auth.invokeAfterAuthHandled(() => this.router.navigate(['/']));
  }
}
