export interface AuthConfig {
  responseType: 'code';
  clientId: string;
  redirectUri: string;
  postLogoutRedirectUri: string;
  issuer: string;
  scope: string;
  authorizeEndpoint?: string;
  tokenEndpoint?: string;
  endsessionEndpoint?: string;
  jwks?: any;
  queryParams?: QueryParams;
  validateDiscovery?: boolean;
  discovery?: boolean;
  clockSkewSeconds?: number;
}

export interface AuthorizeUrlParams {
  response_type: 'code';
  client_id: string;
  redirect_uri: string;
  scope: string;
  state?: string;
  response_mode?: 'query' | 'fragment';
  nonce?: string;
  display?: 'page' | 'popup' | 'touch' | 'wap';
  prompt?: 'none' | 'consent' | 'login' | 'select_account';
  max_age?: number;
  ui_locales?: string;
  id_token_hint?: string;
  login_hint?: string;
  acr_values?: string;
  [key: string]: any;
}

export interface AuthErrorParams {
  error:
    | 'access_denied'
    | 'unauthorized_client'
    | 'interaction_required'
    | 'invalid_request'
    | 'invalid_request_uri'
    | 'invalid_request_object'
    | 'login_required'
    | 'unsupported_response_type'
    | 'server_error'
    | 'temporarily_unavailable'
    | 'user_cancelled'
    | 'invalid_client'
    | 'invalid_grant'
    | 'invalid_scope'
    | 'user_selection_required'
    | 'consent_required'
    | 'request_not_supported'
    | 'request_uri_not_supported'
    | 'registration_not_supported';
  error_description?: string;
  error_uri?: string;
  state?: string;
}

export interface DiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
}

export interface IdToken {
  iss: string;
  sub: string;
  aud: string;
  exp: number;
  iat: number;
  auth_time?: number;
  nonce?: string;
  acr?: string;
  amr?: string;
  azp?: string;
  [key: string]: any;
}

export interface AuthResult {
  access_token: string;
  id_token: string;
  refresh_token: string;
  expires_in: number;
  scope: string;
  token_type: string;
}

export interface QueryParams {
  [key: string]: string | number | boolean;
}
