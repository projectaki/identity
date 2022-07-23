import { InjectionToken } from '@angular/core';
import { AuthConfig } from '@zap.io/zap-oidc';

export const AUTH_CONFIG = new InjectionToken<AuthConfig>('AUTH_CONFIG');
