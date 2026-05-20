/** Package-level configuration mirroring Go's `vp.Init(baseURL)`. */
export const vpConfig = {
  baseURL: 'https://api.ndadid.vn/api/v1/did',
};

export function init(baseURL: string): void {
  if (baseURL) vpConfig.baseURL = baseURL;
}
