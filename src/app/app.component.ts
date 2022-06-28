import { Component, inject } from '@angular/core';
import { AuthService } from 'projects/auth/src/public-api';

@Component({
  selector: 'app-root',
  template: ``,
  standalone: true,
})
export class AppComponent {
  private auth = inject(AuthService);

  ngOnInit() {
    this.auth.test();
  }
}
