const BASE = import.meta.env.VITE_API_URL || '/api';

/**
 * Thin API client. The Bearer token lives in localStorage; on 401 the session
 * is cleared and the app returns to /login (handled by onUnauthorized).
 */
let onUnauthorized = () => {};
export function setUnauthorizedHandler(fn) {
  onUnauthorized = fn;
}

export function getToken() {
  return localStorage.getItem('token');
}
export function setToken(token) {
  if (token) localStorage.setItem('token', token);
  else localStorage.removeItem('token');
}

async function request(path, { method = 'GET', body } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;

  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  if (res.status === 401 && token) {
    setToken(null);
    onUnauthorized();
  }

  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

export const api = {
  login: (email, password) => request('/auth/login', { method: 'POST', body: { email, password } }),
  logout: () => request('/auth/logout', { method: 'POST' }),
  me: () => request('/auth/me'),
  targets: () => request('/targets'),
  scans: (params = '') => request(`/scans${params}`),
  createScan: (targetId) => request('/scans', { method: 'POST', body: { targetId } }),
  cancelScan: (id) => request(`/scans/${id}/cancel`, { method: 'POST' }),
  findings: (params = '') => request(`/findings${params}`),
  reports: () => request('/reports'),
  health: () => fetch(`${BASE}/health`).then((r) => r.json()),
};
