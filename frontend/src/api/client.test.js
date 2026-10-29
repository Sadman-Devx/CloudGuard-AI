import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError, apiRequest } from "./client.js";
import { mockFetch } from "../test/mockFetch.js";

afterEach(() => vi.unstubAllGlobals());

describe("apiRequest", () => {
  it("returns parsed JSON on success", async () => {
    mockFetch({ "GET /api/x/": () => ({ body: { ok: true } }) });
    await expect(apiRequest("/api/x/")).resolves.toEqual({ ok: true });
  });

  it("sends a JSON body with content type and custom headers", async () => {
    const { calls } = mockFetch({ "POST /api/x/": () => ({ status: 201, body: {} }) });
    await apiRequest("/api/x/", { method: "POST", body: { a: 1 }, headers: { "X-Source-Name": "f.json" } });
    expect(calls[0].body).toEqual({ a: 1 });
    expect(calls[0].headers["Content-Type"]).toBe("application/json");
    expect(calls[0].headers["X-Source-Name"]).toBe("f.json");
  });

  it("turns the backend error envelope into an ApiError", async () => {
    const details = [{ path: "vpcs[0].cidr", code: "invalid_cidr", message: "bad" }];
    mockFetch({
      "POST /api/x/": () => ({
        status: 422,
        body: { error: { code: "invalid_configuration", message: "rejected", details, request_id: "abc12345" } },
      }),
    });
    const error = await apiRequest("/api/x/", { method: "POST", body: {} }).catch((e) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 422, code: "invalid_configuration", message: "rejected", details });
    expect(error.requestId).toBe("abc12345");
  });

  it("falls back to a generic error when the body is not the envelope", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("<html>boom</html>", { status: 502 })));
    const error = await apiRequest("/api/x/").catch((e) => e);
    expect(error).toMatchObject({ status: 502, code: "http_error" });
    expect(error.message).toContain("502");
  });

  it("reports network failures with a friendly message", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => Promise.reject(new TypeError("Failed to fetch"))));
    const error = await apiRequest("/api/x/").catch((e) => e);
    expect(error).toMatchObject({ status: 0, code: "network_error" });
  });

  it("lets aborts propagate untouched", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Promise.reject(Object.assign(new Error("aborted"), { name: "AbortError" }))),
    );
    await expect(apiRequest("/api/x/")).rejects.toMatchObject({ name: "AbortError" });
  });

  it("can return the body of explicitly accepted non-2xx statuses", async () => {
    mockFetch({ "GET /api/x/": () => ({ status: 503, body: { status: "degraded" } }) });
    await expect(apiRequest("/api/x/", { acceptStatuses: [503] })).resolves.toEqual({ status: "degraded" });
  });
});
