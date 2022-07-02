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
