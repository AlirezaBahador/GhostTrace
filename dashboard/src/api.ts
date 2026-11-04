import type { Event, Health, Metrics, Page, ProcessView, Rule, Tree } from './types';

let accessToken = '';
export function setToken(value: string) { accessToken = value.trim(); }

export async function request<T>(path: string, signal?: AbortSignal): Promise<T> {
  const response = await fetch(path, {
    signal,
    headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : {},
    credentials: 'omit',
    cache: 'no-store',
  });
  if (!response.ok) {
    let reason = `HTTP ${response.status}`;
    try { const body = await response.json() as { error?: { message?: string } }; reason = body.error?.message || reason; } catch { /* not JSON */ }
    throw new Error(reason);
  }
  return response.json() as Promise<T>;
}
export const api = {
  health: (signal?: AbortSignal) => request<Health>('/api/v1/health', signal),
  metrics: (signal?: AbortSignal) => request<Metrics>('/api/v1/metrics', signal),
  events: (params: URLSearchParams, signal?: AbortSignal) => request<Page<Event>>(`/api/v1/events?${params}`,signal),
  alerts: (params: URLSearchParams, signal?: AbortSignal) => request<Page<Event>>(`/api/v1/alerts?${params}`,signal),
  processes: (signal?: AbortSignal) => request<Page<ProcessView>>('/api/v1/processes?limit=200',signal),
  tree: (id: string, signal?: AbortSignal) => request<Tree>(`/api/v1/processes/${encodeURIComponent(id)}/tree`, signal),
  rules: (signal?: AbortSignal) => request<{items:Rule[];source:string}>('/api/v1/rules',signal),
};
