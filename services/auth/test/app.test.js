import { describe, expect, test } from "@jest/globals";
import { authHealth } from "../src/app.js";
import { isAllowedWebOrigin, loadConfig } from "../src/config.js";

describe("auth service boundary", () => {
  test("exposes a minimal health payload", () => {
    expect(authHealth()).toEqual({ status: "ok", service: "auth" });
  });

  test("allows only configured production origins while supporting Vite fallback ports locally", () => {
    const local = loadConfig({ NODE_ENV: "development", WEB_ORIGIN: "http://localhost:5173" });
    expect(isAllowedWebOrigin("http://localhost:5174", local)).toBe(true);
    expect(isAllowedWebOrigin("https://outside.example", local)).toBe(false);

    const production = loadConfig({
      NODE_ENV: "production", WEB_ORIGIN: "https://app.example",
      SESSION_SECRET: "s".repeat(32), OTP_HMAC_SECRET: "o".repeat(32), CSRF_SECRET: "c".repeat(32),
    });
    expect(isAllowedWebOrigin("https://app.example", production)).toBe(true);
    expect(isAllowedWebOrigin("http://localhost:5174", production)).toBe(false);
  });
});
