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
    console.log('AppComponent.ngOnInit');
    this.auth.authComplete$.subscribe(x => {
      console.log('auth complete', x);
    });
  }
}
