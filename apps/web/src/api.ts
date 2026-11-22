const API = import.meta.env.PROD ? "" : (import.meta.env.VITE_AUTH_URL || "http://localhost:4000");
export const AUTH_API = API;
export const ENGINE_API = import.meta.env.PROD ? "/engine" : (import.meta.env.VITE_ENGINE_URL || "http://localhost:8000");
let cachedCsrf: string | null = null;

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) { super(message); this.status = status; }
}

async function csrf(): Promise<string> {
  if (cachedCsrf) return cachedCsrf;
  const response = await fetch(`${API}/api/v1/auth/csrf`, { credentials: "include" });
  if (!response.ok) throw new ApiError(response.status, "Your session has expired. Please sign in again.");
  const data = await response.json();
  cachedCsrf = data.csrfToken;
  return cachedCsrf!;
}

export async function post<T>(path: string, body: unknown, authenticated = false): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (authenticated) headers["X-CSRF-Token"] = await csrf();
  const requestBody = JSON.stringify(body);
  let response = await fetch(`${API}${path}`, { method: "POST", headers, credentials: "include", body: requestBody });
  let result = response.status === 204 ? undefined : await response.json().catch(() => ({}));
  if (!authenticated && response.status === 403 && result?.error === "Your session token expired. Refresh and try again.") {
    headers["X-CSRF-Token"] = await csrf();
    response = await fetch(`${API}${path}`, { method: "POST", headers, credentials: "include", body: requestBody });
    result = response.status === 204 ? undefined : await response.json().catch(() => ({}));
  }
  cachedCsrf = null;
  if (!response.ok) throw new ApiError(response.status, result?.error || "Something went wrong. Please try again.");
  return result as T;
}

export async function get<T>(path: string): Promise<T> {
  const response = await fetch(`${API}${path}`, { credentials: "include" });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) throw new ApiError(response.status, result?.error || "Something went wrong.");
  return result as T;
}

async function engineRequest<T>(path: string, init: RequestInit = {}, csrfRequired = false): Promise<T> {
  const headers = new Headers(init.headers);
  if (csrfRequired) headers.set("X-CSRF-Token", await csrf());
  const response = await fetch(`${ENGINE_API}${path}`, { ...init, headers, credentials: "include" });
  const result = response.status === 204 ? undefined : await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = typeof result?.detail === "string" ? result.detail : typeof result?.error === "string" ? result.error : "The analysis service could not complete this request.";
    throw new ApiError(response.status, message);
  }
  cachedCsrf = null;
  return result as T;
}

export function engineGet<T>(path: string): Promise<T> {
  return engineRequest<T>(path);
}

export function enginePost<T>(path: string, body: unknown): Promise<T> {
  return engineRequest<T>(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }, true);
}

export function engineUpload<T>(path: string, form: FormData): Promise<T> {
  return engineRequest<T>(path, { method: "POST", body: form }, true);
}

export async function engineText(path: string): Promise<string> {
  const response = await fetch(`${ENGINE_API}${path}`, { credentials: "include" });
  if (!response.ok) {
    const result = await response.json().catch(() => ({}));
    throw new ApiError(response.status, typeof result?.detail === "string" ? result.detail : "The analysis service could not export this file.");
  }
  return response.text();
}

export async function engineBlob(path: string): Promise<Blob> {
  const response = await fetch(`${ENGINE_API}${path}`, { credentials: "include" });
  if (!response.ok) {
    const result = await response.json().catch(() => ({}));
    throw new ApiError(response.status, typeof result?.detail === "string" ? result.detail : "The analysis service could not export this file.");
  }
  return response.blob();
}

