import { AuthConfig, AuthorizeUrlParams } from './models';
import { base64UrlEncode } from '@identity-auth/encoding';
import { sha256 } from '@identity-auth/hashing';

export const createAuthUrl = (authConfig: AuthConfig, codeChallenge?: string, state?: string) => {
  const { clientId, endPoint, redirectUrl, responseType, audience } = getAuthorizeUrlParameters(authConfig);
  const authUrl = `${endPoint}?response_type=${responseType}&client_id=${clientId}&redirect_uri=${encodeURIComponent(
    redirectUrl
  )}${state ? `&state=${state}` : ''}${audience ? `&audience=${encodeURIComponent(audience)}` : ''}${
    codeChallenge ? `&code_challenge=${codeChallenge}` : ''
  }${codeChallenge ? `&code_challenge_method=S256` : ''}`;

  function getAuthorizeUrlParameters(authConfig: AuthConfig): AuthorizeUrlParams {
    const { responseType, clientId, redirectUrl, audience, issuer, authorizeEndpoint } = authConfig;
    const authEndpoint = false ? '' : authorizeEndpoint;

    const params = {
      clientId,
      redirectUrl,
      responseType,
      endPoint: authEndpoint,
    } as AuthorizeUrlParams;
    if (audience) params.audience = audience;
    return params;
  }

  return authUrl;
};

export const createTokenUrl = (authConfig: AuthConfig) => {
  const url = false ? '' : authConfig.tokenEndpoint;
  return url!;
};

export const createTokenRequestBody = (authConfig: AuthConfig, code: string, codeVerifier?: string) => {
  const grantType = 'authorization_code';
  const body = `grant_type=${grantType}&code=${code}&redirect_uri=${encodeURIComponent(
    authConfig.redirectUrl
  )}&client_id=${authConfig.clientId}&code_verifier=${codeVerifier}`;
  return body;
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

export const createDiscoveryUrl = (authConfig: AuthConfig) => {
  const route = '/.well-known/openid-configuration';
  const issuer = authConfig.issuer;
  const issuerWithoutTrailingSlash = issuer.endsWith('/') ? issuer.slice(0, -1) : issuer;
  return `${issuerWithoutTrailingSlash}${route}`;
};
