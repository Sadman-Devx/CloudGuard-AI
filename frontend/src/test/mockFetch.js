import { vi } from "vitest";

/**
 * Install a fetch mock driven by a route table: { "GET /api/health/": () => ({status, body}) }.
 * Handlers receive the parsed request; unmatched calls fail the test loudly.
 */
export function mockFetch(routes) {
  const calls = [];
  const fn = vi.fn(async (url, init = {}) => {
    const method = init.method ?? "GET";
    const key = `${method} ${url}`;
    const handler = routes[key];
    if (!handler) throw new Error(`Unexpected request: ${key}`);
    const request = { url, method, headers: init.headers ?? {}, body: init.body ? JSON.parse(init.body) : undefined };
    calls.push(request);
    const { status = 200, body = null } = (await handler(request)) ?? {};
    return new Response(body === null ? "" : JSON.stringify(body), { status });
  });
  vi.stubGlobal("fetch", fn);
  return { fn, calls };
}
