// Minimal fetch wrapper that understands the backend's error envelope:
//   {"error": {"code", "message", "details"?, "request_id"?}}

const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "";

export class ApiError extends Error {
  constructor({ status, code, message, details, requestId }) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.details = details;
    this.requestId = requestId;
  }
}

async function readJson(response) {
  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

/**
 * @param {string} path e.g. "/api/projects/"
 * @param {{method?: string, body?: unknown, headers?: Record<string,string>, signal?: AbortSignal,
 *          acceptStatuses?: number[]}} [options] acceptStatuses: non-2xx codes whose body is returned as data.
 */
export async function apiRequest(path, options = {}) {
  const { method = "GET", body, headers = {}, signal, acceptStatuses = [] } = options;
  const init = { method, signal, headers: { Accept: "application/json", ...headers } };
  if (body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(body);
  }

  let response;
  try {
    response = await fetch(`${BASE_URL}${path}`, init);
  } catch (cause) {
    if (cause?.name === "AbortError") throw cause;
    throw new ApiError({
      status: 0,
      code: "network_error",
      message: "Cannot reach the CloudGuard API. Is the backend running?",
    });
  }

  const payload = await readJson(response);
  if (response.ok || acceptStatuses.includes(response.status)) return payload;

  const error = payload?.error;
  throw new ApiError({
    status: response.status,
    code: error?.code ?? "http_error",
    message: error?.message ?? `Request failed (HTTP ${response.status}).`,
    details: error?.details,
    requestId: error?.request_id,
  });
}
