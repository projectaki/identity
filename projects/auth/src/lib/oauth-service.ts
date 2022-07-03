import {
  createAuthUrl,
  createCodeVerifierCodeChallengePair,
  createNonce,
  createTokenRequestBody,
  createTokenUrl,
} from '@identity-auth/core';
import { AuthConfig } from '@identity-auth/models';
import { getAuthStorage, removeFromAuthStorage, setAuthStorage } from '@identity-auth/storage';

export class OAuthService {
  private authConfig!: AuthConfig;

  /**
   * Creates the auth URL and redirects to it.
   *
   * Description:
   * Creates a nonce for the "state" param and generates a code verifier and code challenge.
   * The state and code verifier gets saved in the session storage, as it is needed after the redirect. (cannot be kept in memory)
   */
  login = () => {
    const state = createNonce(16);
    const { codeVerifier, codeChallenge } = createCodeVerifierCodeChallengePair();
    setAuthStorage('state', state);
    setAuthStorage('codeVerifier', codeVerifier);
    const authUrl = createAuthUrl(this.authConfig, codeChallenge, state);
    location.href = authUrl;
  };

  /**
   * Called once when bootstrapping the app to configure the auth service.
   * @param authConfig
   */
  setAuthConfig = (authConfig: AuthConfig) => {
    const redirectUrl = encodeURIComponent(authConfig.redirectUrl);
    const aud = authConfig.audience ? encodeURIComponent(authConfig.audience) : '';

    this.authConfig = {
      ...authConfig,
      redirectUrl,
    };

    if (aud) {
      this.authConfig.audience = aud;
    }
  };

  /**
   *
   * @param func A callback function which gets called when getting the access token.
   * @returns A Promise which resolves with the access token, or null if there is no access token.
   */
  getAccessToken = (func?: (x: any) => void): Promise<any> => {
    return new Promise((resolve, reject) => {
      const token = getAuthStorage().authResult?.access_token;
      if (token) {
        resolve(token);
      } else resolve(null);
    }).then(x => {
      if (func) func(x);
      return x;
    });
  };

  /**
   * Handler for the authentication redirect. Needs to be called in the redirect route.
   * Will vallidate the "state" param, and handle the flow based on the grant type.
   * @param func A callback function to call after the auth flow is completed.
   * @returns Promise<boolean>
   */
  handleAuthResult = (func?: (x: any) => void) => {
    const params = new URLSearchParams(document.location.search);
    this.checkState(params);
    return this.handleCodeFlowRedirect(params).then(x => {
      if (func) func(x);
      return x;
    });
  };

  private handleCodeFlowRedirect = (params: URLSearchParams): Promise<boolean> => {
    return new Promise(async (resolve, reject) => {
      if (!params.has('code')) {
        return resolve(false);
      }
      const code = params.get('code')!;

      try {
        const data = await this.fetchAccessToken(code);
        setAuthStorage('authResult', data);
        removeFromAuthStorage('codeVerifier');
        document.location.href = decodeURIComponent(this.authConfig.redirectUrl);
        return resolve(true);
      } catch (err) {
        return reject(err);
      }
    });
  };

  private fetchAccessToken = async (code: string) => {
    const { codeVerifier } = getAuthStorage();
    const tokenEndpoint = createTokenUrl(this.authConfig);
    const body = createTokenRequestBody(this.authConfig, code, codeVerifier);
    const response = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: body,
    });

    return response.json();
  };

  private checkState = (params: URLSearchParams) => {
    const state = params.get('state');
    const authStorage = getAuthStorage();
    if (authStorage.state && !state) throw new Error('Missing state parameter from redirect');
    if (!authStorage.state && state) throw new Error('Missing state in storage but expected one');
    if (authStorage.state && authStorage.state !== state) throw new Error('Invalid state');
    if (authStorage.state && state) removeFromAuthStorage('state');
  };
}
