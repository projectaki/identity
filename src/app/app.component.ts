import { Component, inject } from '@angular/core';
import { Router, RouterModule } from '@angular/router';
import { AuthService } from '@zap.io/zap-oidc-angular';

@Component({
  selector: 'app-root',
  imports: [RouterModule],
  template: `<router-outlet></router-outlet>`,
  standalone: true,
})
export class AppComponent {
  protected auth = inject(AuthService);
  private router = inject(Router);

  ngOnInit(): void {
    this.auth.authResult$.subscribe(x => {
      //console.log('auth complete', x);
    });

    this.auth.isAuthenticated$.subscribe(x => {
      //console.log('isAuthenticated', x);
    });
  }
}
