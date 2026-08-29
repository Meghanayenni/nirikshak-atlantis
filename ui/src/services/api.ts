/**
 * The one place the frontend talks to the network.
 *
 * No component calls `fetch` directly. Everything goes through `request()`, so
 * authentication, error shape and failure handling are decided once instead of
 * being re-invented per screen.
 *
 * **Failures are never swallowed.** Every non-2xx response becomes an
 * `ApiError` carrying the status and the backend's own `detail` string. The
 * backend's messages are written for operators — "the platform for this file was
 * not identified, so no vendor pack applies and nothing can be audited. This is
 * UNKNOWN, not a failure." — and replacing that with "Something went wrong"
 * would throw away the most useful thing on the screen.
 */

import type { Role } from '@/types/api';

/** Credentials live in memory and in sessionStorage, never in localStorage. */
const STORAGE_KEY = 'nirikshak.session';

export class ApiError extends Error {
  readonly status: number;
  readonly detail: string;
  readonly url: string;

  constructor(status: number, detail: string, url: string) {
    super(detail);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
    this.url = url;
  }

  /** 401 — not authenticated. The shell drops to the login screen. */
  get isUnauthenticated(): boolean {
    return this.status === 401;
  }

  /** 403 — authenticated but not permitted. The backend is authoritative. */
  get isForbidden(): boolean {
    return this.status === 403;
  }

  /**
   * 404 — or a resource belonging to somebody else.
   *
   * The API answers 404 rather than 403 for a resource the caller may not see,
   * deliberately: 403 would confirm the id exists.
   */
  get isNotFound(): boolean {
    return this.status === 404;
  }

  /** 503 — the capability exists but this deployment cannot serve it. */
  get isUnavailable(): boolean {
    return this.status === 503;
  }
}

export class NetworkError extends Error {
  constructor(url: string, cause: unknown) {
    super(
      `Could not reach the NIRIKSHAK API. It may not be running, or the network ` +
        `is unavailable. (${url})`,
    );
    this.name = 'NetworkError';
    this.cause = cause;
  }
}

export interface Session {
  username: string;
  /**
   * HTTP Basic credentials.
   *
   * The backend uses HTTP Basic (decision D25 — deliberately small: no sessions,
   * no refresh tokens, no password reset). That means the browser must hold
   * something replayable. `sessionStorage` scopes it to the tab and clears it
   * when the tab closes; `localStorage` would survive indefinitely on a shared
   * machine. This is a real limitation of Basic auth and is stated rather than
   * hidden.
   */
  token: string;
  role: Role;
  userId: string;
}

let session: Session | null = null;

export function loadSession(): Session | null {
  if (session) return session;
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    session = JSON.parse(raw) as Session;
    return session;
  } catch {
    return null;
  }
}

export function setSession(next: Session | null): void {
  session = next;
  try {
    if (next) sessionStorage.setItem(STORAGE_KEY, JSON.stringify(next));
    else sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    // A browser with storage disabled still works for the life of the tab.
  }
}

export function basicToken(username: string, password: string): string {
  return btoa(`${username}:${password}`);
}

export interface RequestOptions {
  method?: 'GET' | 'POST';
  body?: unknown;
  formData?: FormData;
  query?: Record<string, string | number | boolean | undefined | null>;
  /** Credentials for a request made before a session exists (login). */
  token?: string;
  /** Return the raw text body instead of parsing JSON (the HTML report). */
  raw?: boolean;
  signal?: AbortSignal;
}

function buildUrl(path: string, query?: RequestOptions['query']): string {
  if (!query) return path;
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== null && value !== '') {
      params.append(key, String(value));
    }
  }
  const qs = params.toString();
  return qs ? `${path}?${qs}` : path;
}

async function readDetail(response: Response): Promise<string> {
  try {
    const text = await response.text();
    if (!text) return response.statusText || `HTTP ${response.status}`;
    try {
      const parsed = JSON.parse(text) as { detail?: unknown };
      if (typeof parsed.detail === 'string') return parsed.detail;
      if (parsed.detail) return JSON.stringify(parsed.detail);
    } catch {
      return text.slice(0, 500);
    }
    return text.slice(0, 500);
  } catch {
    return response.statusText || `HTTP ${response.status}`;
  }
}

export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { method = 'GET', body, formData, query, token, raw, signal } = options;
  const url = buildUrl(path, query);

  const headers: Record<string, string> = { Accept: raw ? 'text/html' : 'application/json' };
  const auth = token ?? loadSession()?.token;
  if (auth) headers.Authorization = `Basic ${auth}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';

  let response: Response;
  try {
    response = await fetch(url, {
      method,
      headers,
      body: formData ?? (body !== undefined ? JSON.stringify(body) : undefined),
      signal,
    });
  } catch (cause) {
    if (cause instanceof DOMException && cause.name === 'AbortError') throw cause;
    throw new NetworkError(url, cause);
  }

  if (!response.ok) {
    throw new ApiError(response.status, await readDetail(response), url);
  }

  if (raw) return (await response.text()) as unknown as T;

  const text = await response.text();
  if (!text) return undefined as unknown as T;
  try {
    return JSON.parse(text) as T;
  } catch {
    // A malformed body is a failure, not an empty result. Returning `{}` here
    // would render as "no findings" on a screen where findings exist.
    throw new ApiError(
      response.status,
      'The API returned a response that could not be parsed as JSON.',
      url,
    );
  }
}

/** A human-readable message for any thrown value. Never leaks a stack trace. */
export function describeError(error: unknown): string {
  if (error instanceof ApiError) return error.detail;
  if (error instanceof NetworkError) return error.message;
  if (error instanceof Error) return error.message;
  return 'An unexpected error occurred.';
}
