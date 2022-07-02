import { KJUR } from 'jsrsasign';
import { hexToBytes } from '@identity-auth/encoding';

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
