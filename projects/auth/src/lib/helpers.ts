import { KJUR } from 'jsrsasign';

export const getAuthStorage = () => JSON.parse(sessionStorage.getItem('authConfig') ?? '{}');
export const setAuthStorage = (key: string, val: any) => {
  const authConfig = getAuthStorage();
  authConfig[key] = val;
  sessionStorage.setItem('authConfig', JSON.stringify(authConfig));
};
export const removeFromAuthStorage = (key: string) => {
  const authConfig = getAuthStorage();
  delete authConfig[key];
  sessionStorage.setItem('authConfig', JSON.stringify(authConfig));
};

export const createCodeVerifier = () => {
  let bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const res = bytes.map(x => codeVerifierAlphabet.charCodeAt(x % codeVerifierAlphabet.length));
  const id = String.fromCharCode.apply(null, res as any);
  console.log('randomASCIIString', id);
  const codeVerifier = base64UrlEncode(id);
  console.log('codeVerifierUrlEncoded', codeVerifier);
  return codeVerifier;
};

export const createCodeChallenge = (codeVerifier: string) => {
  const codeChallenge = base64UrlEncode(sha256(codeVerifier));
  return codeChallenge;
};

export const sha256 = (str: string) => {
  const hex = KJUR.crypto.Util.sha256(str);
  const asciiOutput = String.fromCharCode(...hexToBytes(hex));
  console.log('sha256Ascii', asciiOutput);
  return asciiOutput;
};

export const sha256Async = async (str: string) => {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  const hash = await crypto.subtle.digest('SHA-256', data);
  const asciiOutput = String.fromCharCode(...Array.from(new Uint8Array(hash)));
  console.log('sha256Async', asciiOutput);
  return asciiOutput;
};

export const hexToBytes = (hex: string) => {
  const bytes = [];
  for (let c = 0; c < hex.length; c += 2) {
    bytes.push(parseInt(hex.substr(c, 2), 16));
  }
  return bytes;
};

export const base64Encode = (str: string) => btoa(str);
export const base64Decode = (str: string) => atob(str);
export const base64UrlEncode = (str: string) =>
  base64Encode(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
export const base64UrlDecode = (str: string) => {
  const padding = str.length % 4;
  const pad = padding > 0 ? new Array(5 - padding).join('=') : '';
  return base64Decode(str.replace(/-/g, '+').replace(/_/g, '/') + pad);
};

const codeVerifierAlphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
