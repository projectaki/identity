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
import { AuthConfig, AuthResult, DiscoveryDocument, QueryParams } from '@identity-auth/models';
import { getAuthStorage, removeFromAuthStorage, setAuthStorage } from '@identity-auth/storage';
import { getCurrentUrl, getQueryParams, redirectTo } from './url-helper';

export class OIDCService {
  private authStateChangeCb: (authState: boolean) => void = () => false;
  private isAuthenticated: boolean = false;
  private authConfig!: AuthConfig;
  private discoveryDocument!: DiscoveryDocument;

  /**
   *
   * @param cb callback function to be called when auth state changes
   */
  setAuthStateChangeCb(cb: (authResult: boolean) => void) {
    this.authStateChangeCb = cb;
  }

  login = async () => {
    const state = createNonce(32);
    const nonce = createNonce(32);
    const { codeVerifier, codeChallenge } = createCodeVerifierCodeChallengePair();
    setAuthStorage('state', state);
    setAuthStorage('nonce', nonce);
    setAuthStorage('codeVerifier', codeVerifier);
    const authUrl = createAuthUrlFromConfig(this.authConfig, state, nonce, codeChallenge);
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
    const token: string = getAuthStorage().authResult?.access_token;
    if (token) {
      return token;
    }

    return null;
  };

  getIdToken = (): string | null => {
    const token: string = getAuthStorage().authResult?.id_token;
    if (!token) return null;

    const isValid = this.hasValidIdToken(token);
    if (isValid) return token;

    throw new Error('No valid id token found!');
  };

  hasValidIdToken = (inputToken?: string): boolean => {
    const token: string | undefined = inputToken ?? getAuthStorage().authResult?.id_token;
    const isValid: boolean = !!token && validateIdToken(token, this.authConfig, getAuthStorage().nonce);

    return isValid;
  };

  /**
   * Initialize the authentication flow. Loads the discovery document (optionally from config) and stores it in the service. Checks
   * if all of the configs are proprely set.
   * @param authConfig AuthConfig
   * @param authResultCb Callback to be called when auth redirect has been processed and validated. Returns the auth result,
   * if the id token was valid, and returns void if the redirect uri route was loaded without query params.
   */
  initAuth = async (authConfig: AuthConfig, authResultCb?: (x: AuthResult | void) => void): Promise<void> => {
    this.setAuthConfig(authConfig);
    try {
      if (authConfig.discovery == null || authConfig.discovery) {
        await this.loadDiscoveryDocument();
      }
      this.ensureAllConfigIsLoaded();
      await this.runAuthFlow(authResultCb);
    } catch (e) {
      console.log(e);
      throw e;
    }
  };

  private runAuthFlow = async (authResultCb?: (x: AuthResult | void) => void) => {
    const url = getCurrentUrl();
    const queryParams = getQueryParams();

    if (url.startsWith(this.authConfig.redirectUri) && queryParams.toString()) {
      await handleRedirectRouteWithQueryParams.call(this);
    } else if (url.startsWith(this.authConfig.redirectUri) && !queryParams.toString()) {
      handleRedirectRouteWithoutQueryParams.call(this);
    } else {
      handleAllRoutesNotRedirectUri.call(this);
    }

    async function handleRedirectRouteWithQueryParams(this: OIDCService) {
      const res = await this.getAuthResult(queryParams);
      this.evaluateAuthState(res.id_token);
      typeof authResultCb === 'function' && authResultCb(res);

      setAuthStorage('authResult', res);
      redirectTo(this.authConfig.redirectUri);
    }

    function handleRedirectRouteWithoutQueryParams(this: OIDCService) {
      typeof authResultCb === 'function' && authResultCb();
      this.evaluateAuthState();
    }

    function handleAllRoutesNotRedirectUri(this: OIDCService) {
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

  private getAuthResult = async (queryParams: URLSearchParams): Promise<AuthResult> => {
    const params = queryParams ?? getQueryParams();
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

  private handleCodeFlowRedirect = async (params: URLSearchParams): Promise<AuthResult> => {
    if (!params.has('code')) throw new Error('No code found in query params!');

    const code = params.get('code')!;

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

  private removeLocalSession = () => {
    removeFromAuthStorage('authResult');
    removeFromAuthStorage('nonce');
    removeFromAuthStorage('codeVerifier');
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
    if (!this.authConfig.jwks) throw new Error('Jwks is required!');
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
