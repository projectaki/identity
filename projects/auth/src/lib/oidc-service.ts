import {
  createAuthUrl,
  createDiscoveryUrl,
  createLogoutUrl,
  createNonce,
  createParamsFromConfig,
  createTokenRequestBody,
  createVerifierAndChallengePair,
  isAuthCallback,
  trimTrailingSlash,
  validateIdToken,
} from '@identity-auth/core';
import { AuthConfig, AuthResult, DiscoveryDocument, QueryParams } from '@identity-auth/models';
import { StorageService } from './storage-service';
import { getQueryParams, isHttps, redirectTo, replaceUrlState } from './url-helper';

export class OIDCService {
  private isAuthenticated: boolean = false;
  private authConfig!: AuthConfig;
  private discoveryDocument!: DiscoveryDocument;
  private storageService = new StorageService();
  private authStateChangeCb: (authState: boolean) => void = () => false;

  /**
   *
   * @param cb callback function to be called when auth state changes
   */
  setAuthStateChangeCb(cb: (authResult: boolean) => void) {
    this.authStateChangeCb = cb;
  }

  setStorageStrategy(storage: Storage) {
    this.storageService.setStorageStrategy(storage);
  }

  login = async (extraParams?: QueryParams) => {
    this.removeLocalSession();
    const state = createNonce(42);
    const [nonce, hashedNonce] = createVerifierAndChallengePair(42);
    const [codeVerifier, codeChallenge] = createVerifierAndChallengePair();
    const params = createParamsFromConfig(this.authConfig, extraParams);
    const mergedParams = { nonce, codeVerifier, sendUserBackTo: window.location.href, ...params };
    this.storageService.set('state', state);
    this.storageService.set(state, mergedParams);
    const authUrl = createAuthUrl(
      this.authConfig.authorizeEndpoint!,
      { ...params, state, nonce: hashedNonce },
      codeChallenge
    );
    redirectTo(authUrl);
  };

  /**
   *
   * @param logoutCb Callback to be called when logout is complete.
   */
  localLogout = () => {
    this.removeLocalSession();
    redirectTo(this.authConfig.postLogoutRedirectUri);
  };

  logout = (queryParams?: QueryParams) => {
    if (!this.authConfig.endsessionEndpoint) throw new Error('Endsession endpoint is not set!');

    this.removeLocalSession();
    const logoutUrl = createLogoutUrl(this.authConfig.endsessionEndpoint, queryParams);
    redirectTo(logoutUrl);
  };

  getAccessToken = (): string | null => {
    const session = this.getLocalSession();

    return session?.authResult.access_token;
  };

  getIdToken = (): string | null => {
    const session = this.getLocalSession();
    const token: string = session?.authResult.id_token;

    if (!token) return null;
    const isValid = this.hasValidIdToken(token);

    return isValid ? token : null;
  };

  /**
   * Initialize the authentication flow. Loads the discovery document (optionally from config) and stores it in the service. Checks
   * if all of the configs are proprely set.
   * @param authConfig AuthConfig
   * @param authResultCb Callback to be called when auth redirect has been processed and validated. Returns the auth result,
   * if the id token was valid, and returns void if the redirect uri route was loaded without query params.
   */
  initAuth = async (authConfig: AuthConfig, authResultCb?: (x: AuthResult) => void): Promise<void> => {
    this.setAuthConfig(authConfig);
    if (authConfig.discovery == null || authConfig.discovery) {
      await this.loadDiscoveryDocument();
    }
    this.ensureAllConfigIsLoaded();
    if (authConfig.useHttps !== false) this.tlsCheck();
    try {
      await this.runAuthFlow(authResultCb);
    } catch (e) {
      console.error(e);
      throw e;
    }
  };

  private hasValidIdToken = (inputToken?: string): boolean => {
    const session = this.getLocalSession();

    if (!session) return false;
    const { authResult, nonce, max_age } = session;
    const token: string = inputToken ?? authResult.id_token;
    const isValid: boolean = validateIdToken(token, this.authConfig, nonce, max_age);

    return isValid;
  };

  private runAuthFlow = async (authResultCb?: (x: AuthResult) => void) => {
    if (isAuthCallback(this.authConfig)) {
      const res = await this.getAuthResult();
      this.evaluateAuthState(res.id_token);
      typeof authResultCb === 'function' && authResultCb(res);
      const session = this.getLocalSession();
      this.storageService.set(this.storageService.get('state'), { ...session, authResult: res });
      const { sendUserBackTo } = session;
      if (sendUserBackTo && this.authConfig.preserveRoute !== false) replaceUrlState(sendUserBackTo);
    } else {
      this.evaluateAuthState();
    }
  };

  private loadDiscoveryDocument = async (
    discoveryLoadedCb?: (x: DiscoveryDocument) => void,
    jwksLoadedCb?: (x: any) => void
  ): Promise<void> => {
    // TODO: add a cache for the discovery document
    const url = createDiscoveryUrl(this.authConfig.issuer);
    try {
      const response = await fetch(url, { method: 'GET' });
      const discoveryDocument = await response.json();
      if (this.authConfig.validateDiscovery == null || !!this.authConfig.validateDiscovery)
        this.validateDiscoveryDocument(discoveryDocument);
      this.discoveryDocument = discoveryDocument;
      typeof discoveryLoadedCb === 'function' && discoveryLoadedCb(discoveryDocument);

      this.authConfig.authorizeEndpoint = this.discoveryDocument.authorization_endpoint;
      this.authConfig.tokenEndpoint = this.discoveryDocument.token_endpoint;

      const jwks = await this.loadJwks();
      this.authConfig.jwks = jwks;
      typeof jwksLoadedCb === 'function' && jwksLoadedCb(discoveryDocument);
    } catch (e) {
      console.error(e);
      throw e;
    }
  };

  private getAuthResult = async (): Promise<AuthResult> => {
    const params = getQueryParams();
    this.checkState(params);

    if (params.has('error')) throw new Error(params.get('error')!);

    try {
      if (this.authConfig.responseType === 'code') {
        const authResult = await this.handleCodeFlowRedirect(params);

        return authResult;
      } else return {} as AuthResult; // until other cases implemented
    } catch (e) {
      console.error(e);
      throw e;
    }
  };

  private checkState = (params: URLSearchParams) => {
    const returnedState = params.get('state');
    if (!returnedState) throw new Error('State expected from query params!');
    const storedState = this.storageService.get('state');
    if (storedState !== returnedState) throw new Error('Invalid state!');
  };

  private handleCodeFlowRedirect = async (params: URLSearchParams): Promise<AuthResult> => {
    if (!params.has('code')) throw new Error('No code found in query params!');

    const code = params.get('code')!;
    replaceUrlState(this.authConfig.redirectUri);

    try {
      const data = await this.fetchTokensWithCode(code);

      return data;
    } catch (err) {
      throw err;
    }
  };

  private setAuthConfig = (authConfig: AuthConfig) => {
    this.authConfig = authConfig;
  };

  private setAuthState = (authState: boolean) => {
    this.isAuthenticated = authState;
    this.authStateChangeCb(authState);
  };

  private evaluateAuthState = (token?: string) => {
    const isAuthed = this.hasValidIdToken(token);
    this.setAuthState(isAuthed);

    return isAuthed;
  };

  private getLocalSession = () => {
    const state = this.storageService.get('state');
    if (!state) return null;

    return this.storageService.get(state);
  };

  private removeLocalSession = () => {
    const state = this.storageService.get('state');
    this.storageService.remove('state');
    this.storageService.remove(state);
    this.setAuthState(false);
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

  private fetchTokensWithCode = async (code: string): Promise<AuthResult> => {
    const { codeVerifier } = this.getLocalSession();
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

  private ensureAllConfigIsLoaded = () => {
    if (!this.authConfig) throw new Error('Missing authConfig');
    if (!this.authConfig.authorizeEndpoint)
      throw new Error('Authorization endpoint is required, if not using discovery!');
    if (!this.authConfig.tokenEndpoint) throw new Error('Token endpoint is required, if not using discovery!');
    if (!this.authConfig.jwks) throw new Error('Jwks is required!');
  };

  private validateDiscoveryDocument(discoveryDocument: DiscoveryDocument) {
    if (!discoveryDocument) throw new Error('Discovery document is required!');

    const issuerWithoutTrailingSlash = trimTrailingSlash(discoveryDocument.issuer);
    if (issuerWithoutTrailingSlash !== this.authConfig.issuer) throw new Error('Invalid issuer in discovery document');
  }

  private tlsCheck = () => {
    if (!isHttps(this.authConfig.issuer)) throw new Error('TLS check failed for issuer!');
    if (!isHttps(this.authConfig.authorizeEndpoint!)) throw new Error('TLS check failed for authorize endpoint!');
    if (!isHttps(this.authConfig.tokenEndpoint!)) throw new Error('TLS check failed for token endpoint!');
    if (!isHttps(this.authConfig.endsessionEndpoint!)) throw new Error('TLS check failed for end session endpoint!');
  };
}
