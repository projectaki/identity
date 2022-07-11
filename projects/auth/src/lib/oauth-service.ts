import {
  createAuthUrl,
  createAuthUrlFromConfig,
  createCodeVerifierCodeChallengePair,
  createDiscoveryUrl,
  createLogoutUrl,
  createNonce,
  createTokenRequestBody,
  trimIssuerOfTrailingSlash,
  validateIdToken,
} from '@identity-auth/core';
import { AuthConfig, AuthResult, DiscoveryDocument } from '@identity-auth/models';
import { getAuthStorage, removeFromAuthStorage, setAuthStorage } from '@identity-auth/storage';

export class OAuthService {
  public isAuthenticated: boolean = false;
  private authConfig!: AuthConfig;
  private discoveryDocument!: DiscoveryDocument;

  /**
   * Creates the auth URL and redirects to it.
   *
   * Description:
   * Creates a nonce for the "state" param and generates a code verifier and code challenge.
   * The state and code verifier gets saved in the session storage, as it is needed after the redirect. (cannot be kept in memory)
   * If the discovery document was not loaded on bootstrap, will load it first.
   * @throws Error if the discovery document was not loaded on bootstrap AND required endpoints are not set explicitly.
   */
  login = async (func?: () => void) => {
    this.ensureAllConfigIsLoaded();

    const state = createNonce(32);
    const nonce = createNonce(32);
    const { codeVerifier, codeChallenge } = createCodeVerifierCodeChallengePair();
    setAuthStorage('state', state);
    setAuthStorage('nonce', nonce);
    setAuthStorage('codeVerifier', codeVerifier);
    const authUrl = createAuthUrlFromConfig(this.authConfig, state, nonce, codeChallenge);
    location.href = authUrl;
    if (func) func();
  };

  localLogout = (func?: () => void) => {
    this.removeLocalSession();
    location.href = this.authConfig.postLogoutRedirectUri;
    if (func) func();
  };

  logout = (func?: () => void) => {
    if (!this.authConfig.endsessionEndpoint) throw new Error('Endsession endpoint is not set!');

    this.removeLocalSession();
    const logoutUrl = createLogoutUrl(this.authConfig.endsessionEndpoint, {
      returnTo: this.authConfig.postLogoutRedirectUri,
      client_id: this.authConfig.clientId,
    });
    location.href = logoutUrl;
    if (func) func();
  };

  /**
   * Called once when bootstrapping the app to configure the auth service.
   * @param authConfig
   */
  setAuthConfig = (authConfig: AuthConfig) => {
    this.authConfig = authConfig;
  };

  getAccessToken = (func?: (x: any) => void): string | null => {
    const token: string = getAuthStorage().authResult?.access_token;
    if (token) {
      return token;
    }
    if (func) func(token);
    return null;
  };

  getIdToken = (func?: (x: string) => void): string | null => {
    const token: string = getAuthStorage().authResult?.id_token;
    if (!token) {
      if (func) func(token);
      return null;
    }
    const isValid = this.hasValidIdToken(token);
    if (isValid) {
      if (func) func(token);
      return token;
    }
    throw new Error('No valid id token found!');
  };

  hasValidIdToken = (inputToken?: string): boolean => {
    const token = inputToken ?? getAuthStorage().authResult?.id_token;
    const isValid = token && validateIdToken(token, this.authConfig, getAuthStorage().nonce);

    return isValid;
  };

  /**
   * Handler for the authentication redirect. Needs to be called in the redirect route.
   * Will vallidate the "state" param, and handle the flow based on the grant type.
   * @param func A callback function to call after the auth flow is completed.
   * @returns Promise<boolean>
   */
  handleAuthResult = async (func?: (x: AuthResult) => void): Promise<AuthResult | void> => {
    this.ensureAllConfigIsLoaded();
    if (this.hasValidIdToken()) {
      this.isAuthenticated = true;
      return getAuthStorage().authResult;
    }
    const params = new URLSearchParams(document.location.search);
    this.checkState(params);
    try {
      const x_1 = await this.handleCodeFlowRedirect(params);
      this.isAuthenticated = true;
      if (x_1) location.href = this.authConfig.redirectUri;
      if (func) func(x_1!);
      return x_1;
    } catch (e) {
      console.error(e);
      throw e;
    }
  };

  /**
   * Should be called on application bootstrap, to get the discovery document.
   * Load the discovery document using the issuer provided in the authConfig.
   * @param func A callback function to call after the discovery document is loaded.
   */
  loadDiscoveryDocument = async (func?: (x: DiscoveryDocument) => void): Promise<void> => {
    const url = createDiscoveryUrl(this.authConfig.issuer);
    try {
      const response = await fetch(url, { method: 'GET' });
      const discoveryDocument = await response.json();
      if (this.authConfig.validateDiscovery == null || !!this.authConfig.validateDiscovery)
        this.validateDiscoveryDocument(discoveryDocument);
      this.discoveryDocument = discoveryDocument;
      this.authConfig.authorizeEndpoint = this.discoveryDocument.authorization_endpoint;
      this.authConfig.tokenEndpoint = this.discoveryDocument.token_endpoint;

      const jwks = await this.loadJwks();
      this.authConfig.jwks = jwks;
      console.log(jwks);

      if (func) func(discoveryDocument);
      console.log(discoveryDocument);
    } catch (e) {
      console.error(e);
      throw e;
    }
  };

  private removeLocalSession = () => {
    removeFromAuthStorage('authResult');
    removeFromAuthStorage('nonce');
    removeFromAuthStorage('codeVerifier');
    this.isAuthenticated = false;
  };

  private loadJwks = async () => {
    const url = `${this.discoveryDocument.jwks_uri}`;
    try {
      const response = await fetch(url, { method: 'GET' });
      const jwks = await response.json();

      return jwks;
    } catch (e) {
      throw e;
    }
  };

  private handleCodeFlowRedirect = async (params: URLSearchParams): Promise<AuthResult | void> => {
    if (params.has('error')) {
      throw new Error(params.get('error')!);
    }
    if (!params.has('code')) {
      return;
    }
    const code = params.get('code')!;

    try {
      const data = await this.fetchTokens(code);
      const { id_token } = data;
      const { nonce } = getAuthStorage();
      validateIdToken(id_token, this.authConfig, nonce);
      setAuthStorage('authResult', data);

      return data;
    } catch (err) {
      throw err;
    }
  };

  private fetchTokens = async (code: string): Promise<AuthResult> => {
    const { codeVerifier } = getAuthStorage();
    const body = createTokenRequestBody(this.authConfig, code, codeVerifier);
    try {
      const response = await fetch(this.authConfig.tokenEndpoint!, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: body,
      });

      return response.json();
    } catch (err) {
      throw err;
    }
  };

  private checkState = (params: URLSearchParams) => {
    const state = params.get('state');
    const authStorage = getAuthStorage();
    if (authStorage.state && !state) throw new Error('Missing state parameter from redirect');
    if (!authStorage.state && state) throw new Error('Missing state in storage but expected one');
    if (authStorage.state && authStorage.state !== state) throw new Error('Invalid state');
    if (authStorage.state && state) removeFromAuthStorage('state');
  };

  private ensureAllConfigIsLoaded = () => {
    if (!this.authConfig) throw new Error('Missing authConfig');
    if (!this.authConfig.authorizeEndpoint)
      throw new Error('Authorization endpoint is required, if not using discovery!');
    if (!this.authConfig.tokenEndpoint) throw new Error('Token endpoint is required, if not using discovery!');
    if (!this.authConfig.jwks) throw new Error('Jwsk is required!');
  };

  private validateDiscoveryDocument(discoveryDocument: DiscoveryDocument) {
    if (!discoveryDocument) throw new Error('Discovery document is required!');

    const issuerWithoutTrailingSlash = trimIssuerOfTrailingSlash(discoveryDocument.issuer);
    if (issuerWithoutTrailingSlash !== this.authConfig.issuer) throw new Error('Invalid issuer in discovery document');
  }

  // Test method remove later
  validate(idToken: string) {
    validateIdToken(idToken, this.authConfig);
  }
}
