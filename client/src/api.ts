const basePath = import.meta.env.BASE_URL.replace(/\/$/, "");

export function apiUrl(path: string): string {
  return `${basePath}${path.startsWith("/") ? path : `/${path}`}`;
}
