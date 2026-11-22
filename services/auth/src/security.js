import { createHmac, createHash, randomBytes, randomInt, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(scryptCallback);
export const normalizeEmail = (email) => email.trim().toLowerCase();
export const digestEmail = (email, secret) => createHmac("sha256", secret).update(normalizeEmail(email)).digest("hex");
export const hashOtp = (otp, secret) => createHmac("sha256", secret).update(otp).digest("hex");
export const hashOpaqueToken = (token) => createHash("sha256").update(token).digest("hex");
export const createOtp = () => String(randomInt(0, 1_000_000)).padStart(6, "0");
export const createOpaqueToken = () => randomBytes(32).toString("base64url");

export async function hashPassword(password) {
  const salt = randomBytes(16);
  const key = await scrypt(password, salt, 64, { N: 1 << 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  return `scrypt$32768$8$1$${salt.toString("base64url")}$${Buffer.from(key).toString("base64url")}`;
}

export async function verifyPassword(password, encoded) {
  const [algorithm, n, r, p, saltText, keyText] = String(encoded || "").split("$");
  if (algorithm !== "scrypt" || !saltText || !keyText) return false;
  try {
    const expected = Buffer.from(keyText, "base64url");
    const actual = Buffer.from(await scrypt(password, Buffer.from(saltText, "base64url"), expected.length, {
      N: Number(n), r: Number(r), p: Number(p), maxmem: 64 * 1024 * 1024
    }));
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  } catch { return false; }
}

export function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && timingSafeEqual(a, b);
}

export function signCookie(token, secret) {
  const signature = createHmac("sha256", secret).update(token).digest("base64url");
  return `${token}.${signature}`;
}

export function verifyCookie(value, secret) {
  if (!value || typeof value !== "string") return null;
  const dot = value.lastIndexOf(".");
  if (dot < 1) return null;
  const token = value.slice(0, dot);
  const supplied = value.slice(dot + 1);
  const expected = createHmac("sha256", secret).update(token).digest("base64url");
  return safeEqual(supplied, expected) ? token : null;
}

export function csrfToken(sessionToken, secret) {
  return createHmac("sha256", secret).update(`csrf:${sessionToken}`).digest("base64url");
}

export function maskEmail(email) {
  const [name, domain] = email.split("@");
  return `${name.slice(0, 1)}${"*".repeat(Math.max(3, Math.min(8, name.length - 1)))}@${domain}`;
}

