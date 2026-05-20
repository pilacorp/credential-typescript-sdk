/**
 * Package-level configuration mirroring Go's `vc.Init(baseURL)`.
 */
export const vcConfig = {
  baseURL: 'https://api.ndadid.vn/api/v1/did',
};

export function init(baseURL: string): void {
  if (baseURL) vcConfig.baseURL = baseURL;
}
