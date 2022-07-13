import { Component, OnInit } from '@angular/core';

@Component({
  selector: 'app-test-page',
  template: `
    <p>
      test-page works!
    </p>
  `,
  styles: [
  ]
})
export class TestPageComponent implements OnInit {

  constructor() { }

  ngOnInit(): void {
  }

}
