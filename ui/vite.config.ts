/// <reference types="vitest" />
import react from '@vitejs/plugin-react';
import { fileURLToPath, URL } from 'node:url';
import { defineConfig, type ProxyOptions } from 'vite';

/**
 * The API is same-origin in production. In development it runs on :8000 and is
 * proxied here, so the browser never needs CORS and no API host is baked into
 * the bundle.
 *
 * **The prefixes collide with client-side routes, deliberately handled.** The
 * backend owns `/health`, `/users`, `/audit`, `/compliance`, `/training`,
 * `/ingest` and `/fleet`; the interface has routes of its own at `/health`,
 * `/users`, `/audits`, `/compliance` and `/training`. Without the `bypass` below,
 * opening or refreshing one of those pages would be proxied to the API and the
 * operator would see raw JSON or a 401 instead of the screen.
 *
 * `bypass` distinguishes them by what the request is for, which is the only
 * honest signal available: a browser navigating to a page sends
 * `Accept: text/html`, and returning the SPA entry point for those lets React
 * Router resolve the route. Everything else — the application's own `fetch`
 * calls, which ask for JSON — proxies to the API untouched.
 */
const API_TARGET = 'http://127.0.0.1:8000';

function apiProxy(): ProxyOptions {
  return {
    target: API_TARGET,
    changeOrigin: false,
    bypass(req) {
      const accept = req.headers.accept ?? '';
      // A document request from the address bar: serve the application.
      if (req.method === 'GET' && accept.includes('text/html')) return '/index.html';
      // Anything else is an API call and is proxied.
      return undefined;
    },
  };
}

const API_PREFIXES = ['/health', '/ingest', '/compliance', '/fleet', '/training', '/audit', '/users'];

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  server: {
    port: 5173,
    proxy: Object.fromEntries(API_PREFIXES.map((prefix) => [prefix, apiProxy()])),
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    css: false,
  },
});
