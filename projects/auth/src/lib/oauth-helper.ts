import { AuthConfig, AuthorizeUrlParams } from './models';
import { base64UrlEncode } from '@identity-auth/encoding';
import { sha256 } from '@identity-auth/hashing';

export const createAuthUrlFromConfig = (
  authConfig: AuthConfig,
  state?: string,
  nonce?: string,
  codeChallenge?: string
) => {
  const authUrlParams: AuthorizeUrlParams = {
    client_id: authConfig.clientId,
    redirect_uri: authConfig.redirectUri,
    response_type: authConfig.responseType,
    scope: authConfig.scope,
  };
  if (state) authUrlParams.state = state;
  if (nonce) authUrlParams.nonce = nonce;
  const queryParams = authConfig.queryParams;
  if (queryParams) {
    Object.keys(queryParams).forEach(key => {
      authUrlParams[key] = queryParams[key];
    });
  }

  return createAuthUrl(authConfig.authorizeEndpoint!, authUrlParams, codeChallenge);
};

export const createAuthUrl = (url: string, authUrlParams: AuthorizeUrlParams, codeChallenge?: string) => {
  const keys = Object.keys(authUrlParams);
  const queryParams = new URLSearchParams();
  keys.forEach(key => {
    queryParams.append(key, authUrlParams[key]);
  });
  if (codeChallenge) queryParams.append('code_challenge', codeChallenge);
  if (codeChallenge) queryParams.append('code_challenge_method', 'S256');

  const res = `${url}?${queryParams.toString()}`;
  return res;
};

export const createTokenRequestBody = (authConfig: AuthConfig, code: string, codeVerifier?: string) => {
  const grantType = getGrantType(authConfig);
  const urlSearchParam = new URLSearchParams();
  urlSearchParam.append('grant_type', grantType);
  urlSearchParam.append('code', code);
  if (codeVerifier) urlSearchParam.append('code_verifier', codeVerifier);
  urlSearchParam.append('redirect_uri', authConfig.redirectUri);
  urlSearchParam.append('client_id', authConfig.clientId);
  const body = urlSearchParam.toString();

  return body;
};

export const getGrantType = (authConfig: AuthConfig) => {
  const { responseType } = authConfig;
  if (responseType === 'code') {
    return 'authorization_code';
  }
  return 'implicit';
};

export const createCodeVerifierCodeChallengePair = () => {
  const codeVerifier = createNonce(32);
  const codeChallenge = createCodeChallenge(codeVerifier);

  function createCodeChallenge(codeVerifier: string) {
    return base64UrlEncode(sha256(codeVerifier));
  }

  return { codeVerifier, codeChallenge };
};

export const createRandomString = (length: number) => {
  let bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  const randomASCIIString = String.fromCharCode(...bytes);
  return randomASCIIString;
};

export const createNonce = (length: number) => {
  const randomASCIIString = createRandomString(length);
  const nonce = base64UrlEncode(randomASCIIString);
  return nonce;
};

export const createDiscoveryUrl = (issuer: string) => {
  const route = '/.well-known/openid-configuration';
  const issuerWithoutTrailingSlash = issuer.endsWith('/') ? issuer.slice(0, -1) : issuer;
  return `${issuerWithoutTrailingSlash}${route}`;
};
