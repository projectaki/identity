export const redirectTo = (url: string) => {
  location.href = url;
};

export const getCurrentUrl = () => {
  return location.href;
};

export const getQueryParams = () => {
  return new URLSearchParams(location.search);
};
