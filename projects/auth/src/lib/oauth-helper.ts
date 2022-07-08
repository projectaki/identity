import { AuthConfig, AuthorizeUrlParams } from './models';
import { base64Decode, base64UrlDecode, base64UrlEncode } from '@identity-auth/encoding';
import { sha256 } from '@identity-auth/hashing';
import { KEYUTIL, KJUR } from 'jsrsasign';

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
  const issuerWithoutTrailingSlash = trimIssuerOfTrailingSlash(issuer);
  return `${issuerWithoutTrailingSlash}${route}`;
};

export const trimIssuerOfTrailingSlash = (issuer: string) => {
  return issuer.endsWith('/') ? issuer.slice(0, -1) : issuer;
};

/**
 * 
 * @param idToken 


8. If the JWT `alg` Header Parameter uses a MAC based algorithm such as HS256, HS384, or HS512, the octets of the UTF-8 representation of the `client_secret` corresponding to the `client_id` contained in the `aud` (audience) Claim are used as the key to validate the signature. For MAC based algorithms, the behavior is unspecified if the `aud` is multi-valued or if an `azp` value is present that is different than the `aud` value.
9. The current time `**MUST**` be before the time represented by the `exp` Claim.
10. The `iat` Claim can be used to reject tokens that were issued too far away from the current time, limiting the amount of time that nonces need to be stored to prevent attacks. The acceptable range is Client specific.
11. If a nonce value was sent in the Authentication Request, a nonce Claim `**MUST**` be present and its value checked to verify that it is the same value as the one that was sent in the Authentication Request. The Client `**SHOULD**` check the nonce value for replay attacks. The precise method for detecting replay attacks is Client specific.
12. If the `acr` Claim was requested, the Client `**SHOULD**` check that the asserted Claim Value is appropriate. The meaning and processing of `acr` Claim Values is out of scope for this specification.
13. If the `auth_time` Claim was requested, either through a specific request for this Claim or by using the `max_age` parameter, the Client `**SHOULD**` check the `auth_time` Claim value and request re-authentication if it determines too much time has elapsed since the last End-User authentication.
 */
export const validateIdToken = (idToken: string, authConfig: AuthConfig) => {
  const [header, payload, signature] = idToken.split('.');
  const decodedHeader = JSON.parse(base64Decode(header));
  const decodedPayload = JSON.parse(base64Decode(payload));
  const decodedSignature = base64UrlDecode(signature);

  checkEncryption();
  validateIssuer();
  validateAudience();
  validateSignature();
  validateAlg();

  //1. If the ID Token is encrypted, decrypt it using the keys and algorithms that the Client specified during Registration that the OP was to use to encrypt the ID Token. If encryption was negotiated with the OP at Registration time and the ID Token is not encrypted, the RP `**SHOULD**` reject it.
  function checkEncryption() {}

  //2. The Issuer Identifier for the OpenID Provider (which is typically obtained during Discovery) `**MUST**` exactly match the value of the `iss` (issuer) Claim.
  function validateIssuer() {
    const registeredIssuerWithoutTrailingSlash = trimIssuerOfTrailingSlash(authConfig.issuer);
    const tokenIssuerWithoutTrailingSlash = trimIssuerOfTrailingSlash(decodedPayload.iss);

    if (registeredIssuerWithoutTrailingSlash !== tokenIssuerWithoutTrailingSlash) {
      throw new Error(`Invalid issuer, expected ${authConfig.issuer} but got ${decodedPayload.iss}`);
    }
  }

  /*
3. The Client `**MUST**` validate that the `aud` (audience) Claim contains its `client_id` value registered at the Issuer identified by the `iss` (issuer) Claim as an audience. The `aud` (audience) Claim `**MAY**` contain an array with more than one element. The ID Token `**MUST**` be rejected if the ID Token does not list the Client as a valid audience, or if it contains additional audiences not trusted by the Client.
4. If the ID Token contains multiple audiences, the Client `**SHOULD**` verify that an `azp` Claim is present.
5. If an azp (authorized party) Claim is present, the Client `**SHOULD**` verify that its `client_id` is the Claim Value.
  */
  function validateAudience() {
    const audiences = decodedPayload.aud.split(' ');
    if (!audiences.includes(authConfig.clientId)) {
      throw new Error(`Invalid audience expected ${authConfig.clientId} but got ${audiences}`);
    }
    if (audiences.length > 1) {
      if (!decodedPayload.azp) {
        throw new Error('azp claim is required');
      }
      if (decodedPayload.azp !== authConfig.clientId) {
        throw new Error('Invalid azp claim');
      }
    }
  }

  //6. If the ID Token is received via direct communication between the Client and the Token Endpoint (which it is in this flow), the TLS server validation `**MAY**` be used to validate the issuer in place of checking the token signature. The Client `**MUST**` validate the signature of all other ID Tokens according to **[JWS](https://openid.net/specs/openid-connect-core-1_0.html#JWS)** [JWS] using the algorithm specified in the JWT `alg` Header Parameter. The Client `**MUST**` use the keys provided by the Issuer.
  function validateSignature() {
    const { kid, alg } = decodedHeader;

    if (kid) {
      const jwk = authConfig.jwks.keys.find((jwk: any) => jwk.kid === kid);
      const pubKey = KEYUTIL.getKey(jwk) as jsrsasign.RSAKey;

      const isValid = KJUR.jws.JWS.verify(idToken, pubKey, [alg]);
      if (!isValid) {
        throw new Error('Invalid signature');
      }
    } else {
      const jwk = authConfig.jwks.keys[0];
      if (jwk.alg !== alg) throw new Error('There was no kid, and could not find jwk with matching alg');
      const pubKey = KEYUTIL.getKey(jwk) as jsrsasign.RSAKey;

      const isValid = KJUR.jws.JWS.verify(idToken, pubKey, [alg]);
      if (!isValid) {
        throw new Error('Invalid signature');
      }
    }
  }

  //7. The `alg` value `**SHOULD**` be the default of `RS256` or the algorithm sent by the Client in the `id_token_signed_response_alg` parameter during Registration.
  function validateAlg() {
    const { alg } = decodedHeader;
    if (alg !== 'RS256') {
      throw new Error('Invalid algorithm');
    }
  }
};
