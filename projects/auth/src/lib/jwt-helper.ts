export const decodeJWt = (jwt: string) => {
  const parts = jwt.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT');
  }
  try {
    const header = JSON.parse(atob(parts[0]));
    const payload = JSON.parse(atob(parts[1]));
    const signature = parts[2];
    return { header, payload, signature };
  } catch (e) {
    throw new Error('Id token is an invalid JWT, couldnt decode it');
  }
};
