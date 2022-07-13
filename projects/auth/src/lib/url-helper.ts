export const redirectTo = (url: string) => {
  location.href = url;
};

export const getCurrentUrl = () => {
  return location.href;
};
