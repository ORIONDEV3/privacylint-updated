import { describe, expect, test } from "@jest/globals";
import { loadConfig } from "../src/config.js";
import {
  createOtp, createOpaqueToken, csrfToken, digestEmail, hashOtp, hashPassword,
  maskEmail, normalizeEmail, signCookie, verifyCookie, verifyPassword
} from "../src/security.js";

describe("authentication primitives", () => {
  test("uses password-only auth locally without mail and refuses it in production", () => {
    expect(loadConfig({ NODE_ENV: "development" }).otpMode).toBe("password");
    expect(loadConfig({ NODE_ENV: "development", SMTP_USER: "sender@example.com", SMTP_PASS: "smtp-password" }).otpMode).toBe("email");
    expect(() => loadConfig({ NODE_ENV: "production", SESSION_SECRET: "s".repeat(32), OTP_HMAC_SECRET: "o".repeat(32), CSRF_SECRET: "c".repeat(32), AUTH_OTP_MODE: "password" })).toThrow("only allowed outside production");
  });

  test("normalizes and masks email addresses", () => {
    expect(normalizeEmail("  DEV@Example.com ")).toBe("dev@example.com");
    expect(maskEmail("neha@example.com")).toBe("n***@example.com");
  });

  test("generates six-digit OTPs and keyed, non-reversible lookup values", () => {
    const otp = createOtp();
    expect(otp).toMatch(/^\d{6}$/);
    expect(hashOtp(otp, "secret")).not.toBe(otp);
    expect(digestEmail("A@B.com", "secret")).toBe(digestEmail("a@b.com", "secret"));
  });

  test("hashes passwords and rejects a different password", async () => {
    const encoded = await hashPassword("a-long-password-for-test");
    expect(encoded.startsWith("scrypt$32768$8$1$")).toBe(true);
    await expect(verifyPassword("a-long-password-for-test", encoded)).resolves.toBe(true);
    await expect(verifyPassword("different-password", encoded)).resolves.toBe(false);
  });

  test("signs cookies and derives session-bound CSRF tokens", () => {
    const token = createOpaqueToken();
    const signed = signCookie(token, "cookie-secret");
    expect(verifyCookie(signed, "cookie-secret")).toBe(token);
    expect(verifyCookie(`${signed}x`, "cookie-secret")).toBeNull();
    expect(csrfToken(token, "csrf-secret")).not.toBe(csrfToken(`${token}x`, "csrf-secret"));
  });
});

