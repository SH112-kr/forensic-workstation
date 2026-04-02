const BASE = '';  // proxy handles /api -> backend

export async function api<T = any>(
  url: string,
  options?: { method?: string; body?: any }
): Promise<T> {
  const { method = 'GET', body } = options || {};
  const res = await fetch(`${BASE}${url}`, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    const message = err.guidance ? `${err.detail}\n\n${err.guidance}` : (err.detail || `HTTP ${res.status}`);
    throw new Error(message);
  }
  return res.json();
}

export const get = <T = any>(url: string) => api<T>(url);
export const post = <T = any>(url: string, body: any) => api<T>(url, { method: 'POST', body });
