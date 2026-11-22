import { randomBytes, randomUUID } from "node:crypto";
import { Router } from "express";
import { z } from "zod";
import { OAuth2Client } from "google-auth-library";
import { pool, withTransaction } from "./db.js";
import { loadConfig } from "./config.js";
import { sendNotice, sendOtp } from "./email.js";
import {
  createOtp, createOpaqueToken, digestEmail, hashOpaqueToken, hashOtp, hashPassword,
  maskEmail, normalizeEmail, signCookie, verifyCookie, verifyPassword, safeEqual, csrfToken
} from "./security.js";

const config = loadConfig();
const router = Router();
const COOKIE_NAME = "pl_session";
const GOOGLE_STATE_COOKIE = "pl_google_state";
const SESSION_TTL_HOURS = 12;
const OTP_MINUTES = 10;
const emailSendWindows = new Map();
const emailAttemptWindows = new Map();
const googleCredentialsPresent = Boolean(config.google.clientId && config.google.clientSecret);
const googleClient = config.google.enabled && googleCredentialsPresent
  ? new OAuth2Client(config.google.clientId, config.google.clientSecret, config.google.redirectUri)
  : null;
const dummyPasswordHash = await hashPassword(createOpaqueToken());

const registerSchema = z.object({ name: z.string().trim().min(2).max(100), email: z.string().email().max(254), password: z.string().min(12).max(128) });
const loginSchema = z.object({ email: z.string().email().max(254), password: z.string().min(1).max(128) });
const otpSchema = z.object({ email: z.string().email().max(254), otp: z.string().regex(/^\d{6}$/), purpose: z.enum(["register", "login", "reset"]) });
const resendSchema = z.object({ email: z.string().email().max(254), purpose: z.enum(["register", "login", "reset"]) });
const resetSchema = z.object({ email: z.string().email().max(254), otp: z.string().regex(/^\d{6}$/), newPassword: z.string().min(12).max(128) });
const roleSchema = z.object({ role: z.enum(["Admin", "Analyst", "Developer"]) });

function parse(schema, req, res) {
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Check the provided information and try again." });
    return null;
  }
  return parsed.data;
}

async function audit(userId, event, outcome, metadata = {}) {
  await pool.query("INSERT INTO audit_logs(user_id,event,outcome,metadata) VALUES($1,$2,$3,$4)", [userId || null, event, outcome, metadata]);
}

function allowEmailSend(email, purpose, isResend = false) {
  const key = digestEmail(email, config.otpSecret);
  const now = Date.now();
  const state = emailSendWindows.get(key) || { all: [], byPurpose: {} };
  state.all = state.all.filter((sent) => now - sent < 60 * 60 * 1000);
  state.byPurpose[purpose] = (state.byPurpose[purpose] || []).filter((sent) => now - sent < 60 * 60 * 1000);
  const purposeRecent = state.byPurpose[purpose];
  if (state.all.length >= 5 || (isResend && purposeRecent.length && now - purposeRecent.at(-1) < 60_000)) {
    emailSendWindows.set(key, state);
    return false;
  }
  state.all.push(now);
  purposeRecent.push(now);
  emailSendWindows.set(key, state);
  if (emailSendWindows.size > 20_000) {
    for (const [entry, value] of emailSendWindows) if (!value.all.length || now - value.all.at(-1) > 60 * 60 * 1000) emailSendWindows.delete(entry);
  }
  return true;
}

function allowEmailAttempt(email) {
  const key = digestEmail(email, config.otpSecret);
  const now = Date.now();
  const recent = (emailAttemptWindows.get(key) || []).filter((at) => now - at < 15 * 60 * 1000);
  if (recent.length >= 12) { emailAttemptWindows.set(key, recent); return false; }
  recent.push(now);
  emailAttemptWindows.set(key, recent);
  return true;
}

async function issueOtp({ userId, email, purpose, isResend = false }) {
  const normalized = normalizeEmail(email);
  const digest = digestEmail(normalized, config.otpSecret);
  const lock = await pool.query("SELECT locked_until FROM otp_codes WHERE email_digest=$1 AND purpose=$2 ORDER BY sent_at DESC LIMIT 1", [digest, purpose]);
  if (lock.rows[0]?.locked_until && new Date(lock.rows[0].locked_until) > new Date()) {
    const error = new Error("Please wait before requesting another code.");
    error.status = 429;
    throw error;
  }
  if (!allowEmailSend(normalized, purpose, isResend)) {
    const error = new Error("Please wait before requesting another code.");
    error.status = 429;
    throw error;
  }
  const otp = createOtp();
  const id = randomUUID();
  await pool.query(
    `INSERT INTO otp_codes(id,user_id,email_digest,purpose,code_hash,expires_at)
     VALUES($1,$2,$3,$4,$5,NOW() + ($6 * INTERVAL '1 minute'))`,
    [id, userId || null, digest, purpose, hashOtp(otp, config.otpSecret), OTP_MINUTES]
  );
  try { await sendOtp({ to: normalized, otp, purpose }); }
  catch (error) {
    await pool.query("UPDATE otp_codes SET consumed_at=NOW() WHERE id=$1", [id]);
    const deliveryError = new Error("Email delivery is temporarily unavailable. Please try again.", { cause: error });
    deliveryError.status = 503;
    throw deliveryError;
  }
  await audit(userId, "otp_sent", "requested", { purpose });
}

function setSessionCookie(res, token) {
  res.cookie(COOKIE_NAME, signCookie(token, config.sessionSecret), {
    httpOnly: true, secure: config.secureCookies, sameSite: "lax", path: "/", maxAge: SESSION_TTL_HOURS * 60 * 60 * 1000
  });
}

function clearGoogleStateCookie(res) {
  res.clearCookie(GOOGLE_STATE_COOKIE, { httpOnly: true, secure: config.secureCookies, sameSite: "lax", path: "/api/v1/auth/google" });
}

function googleLoginError(res, reason = "google_failed") {
  clearGoogleStateCookie(res);
  const origin = config.origins[0] || "http://localhost:5173";
  res.redirect(`${origin}/login?auth_error=${encodeURIComponent(reason)}`);
}

router.get("/config", (_req, res) => res.json({
  emailOtpEnabled: config.otpMode === "email",
  googleEnabled: Boolean(googleClient),
  googleSetupRequired: googleCredentialsPresent && !config.google.enabled
}));

router.get("/google", (req, res) => {
  if (!googleClient) return googleLoginError(res, "google_not_configured");
  const state = randomBytes(32).toString("base64url");
  res.cookie(GOOGLE_STATE_COOKIE, state, {
    httpOnly: true, secure: config.secureCookies, sameSite: "lax", path: "/api/v1/auth/google", maxAge: 5 * 60 * 1000
  });
  res.redirect(googleClient.generateAuthUrl({ scope: ["openid", "email", "profile"], state, prompt: "select_account" }));
});

router.get("/google/callback", async (req, res) => {
  const stateCookie = req.cookies?.[GOOGLE_STATE_COOKIE];
  const stateQuery = typeof req.query.state === "string" ? req.query.state : "";
  if (!googleClient || typeof req.query.code !== "string" || !stateCookie || !safeEqual(stateCookie, stateQuery)) {
    return googleLoginError(res);
  }
  try {
    const { tokens } = await googleClient.getToken(req.query.code);
    if (!tokens.id_token) return googleLoginError(res);
    const ticket = await googleClient.verifyIdToken({ idToken: tokens.id_token, audience: config.google.clientId });
    const claims = ticket.getPayload();
    if (!claims?.sub || !claims.email || claims.email_verified !== true) return googleLoginError(res);
    const email = normalizeEmail(claims.email);
    const outcome = await withTransaction(async (client) => {
      const { rows } = await client.query(
        "SELECT id,name,email,role,google_sub FROM users WHERE google_sub=$1 OR email=$2 LIMIT 1 FOR UPDATE",
        [claims.sub, email]
      );
      const user = rows[0];
      if (!user || (user.google_sub && user.google_sub !== claims.sub)) return null;
      await client.query("UPDATE users SET google_sub=$2,is_verified=TRUE,updated_at=NOW() WHERE id=$1", [user.id, claims.sub]);
      await client.query("DELETE FROM sessions WHERE user_id=$1", [user.id]);
      await createSession(client, user.id, res);
      return user;
    });
    if (!outcome) return googleLoginError(res, "google_account_missing");
    await audit(outcome.id, "google_login", "success", { provider: "google" });
    clearGoogleStateCookie(res);
    const origin = config.origins[0] || "http://localhost:5173";
    return res.redirect(`${origin}/workspace/overview`);
  } catch {
    await audit(null, "google_login", "failure", { provider: "google" }).catch(() => undefined);
    return googleLoginError(res);
  }
});

async function createSession(client, userId, res) {
  const token = createOpaqueToken();
  await client.query("INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,NOW()+INTERVAL '12 hours')", [randomUUID(), userId, hashOpaqueToken(token)]);
  setSessionCookie(res, token);
}

async function getSessionToken(req) {
  return verifyCookie(req.cookies?.[COOKIE_NAME], config.sessionSecret);
}

router.get("/csrf", async (req, res) => {
  const token = await getSessionToken(req);
  if (!token) return res.status(401).json({ error: "Authentication required." });
  const csrf = csrfToken(token, config.csrfSecret);
  res.json({ csrfToken: csrf });
});

router.post("/register", async (req, res, next) => {
  try {
    const input = parse(registerSchema, req, res); if (!input) return;
    const email = normalizeEmail(input.email);
    const passwordHash = await hashPassword(input.password);
    const userId = randomUUID();
    let role = "Developer";
    if (config.bootstrapAdminEmail && email === config.bootstrapAdminEmail) {
      const { rows } = await pool.query("SELECT COUNT(*)::int AS count FROM users");
      if (rows[0].count === 0) role = "Admin";
    }
    try {
      await pool.query("INSERT INTO users(id,name,email,password_hash,role) VALUES($1,$2,$3,$4,$5)", [userId, input.name, email, passwordHash, role]);
    } catch (error) {
      if (error.code === "23505") return res.status(409).json({ error: "Unable to create account with those details." });
      throw error;
    }
    if (config.otpMode === "password") {
      await withTransaction(async (client) => {
        await client.query("UPDATE users SET is_verified=TRUE,updated_at=NOW() WHERE id=$1", [userId]);
        await client.query("DELETE FROM sessions WHERE user_id=$1", [userId]);
        await createSession(client, userId, res);
      });
      await audit(userId, "register", "success", { stage: "local_password_only" });
      return res.status(201).json({ otp_required: false, user: { id: userId, name: input.name, email, role } });
    }
    try { await issueOtp({ userId, email, purpose: "register" }); }
    catch (error) {
      if (/Email delivery is temporarily unavailable/i.test(error.message)) await pool.query("DELETE FROM users WHERE id=$1 AND is_verified=FALSE", [userId]);
      throw error;
    }
    await audit(userId, "register", "requested");
    res.status(202).json({ otp_required: true, message: "If your details are eligible, a verification code is on its way.", email: maskEmail(email) });
  } catch (error) { next(error); }
});

router.post("/login", async (req, res, next) => {
  try {
    const input = parse(loginSchema, req, res); if (!input) return;
    const email = normalizeEmail(input.email);
    if (!allowEmailAttempt(email)) return res.status(429).json({ error: "Too many sign-in attempts. Try again later." });
    const { rows } = await pool.query("SELECT id,name,email,password_hash,is_verified,role FROM users WHERE email=$1", [email]);
    const user = rows[0];
    const passwordOk = await verifyPassword(input.password, user?.password_hash || dummyPasswordHash);
    if (!user || !passwordOk) {
      await audit(user?.id, "login", "failure", { stage: "password" });
      return res.status(401).json({ error: "Email or password is incorrect." });
    }
    if (config.otpMode === "password") {
      await withTransaction(async (client) => {
        if (!user.is_verified) await client.query("UPDATE users SET is_verified=TRUE,updated_at=NOW() WHERE id=$1", [user.id]);
        await client.query("DELETE FROM sessions WHERE user_id=$1", [user.id]);
        await createSession(client, user.id, res);
      });
      await audit(user.id, "login", "success", { stage: "local_password_only" });
      return res.json({ otp_required: false, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
    }
    if (!user.is_verified) {
      await issueOtp({ userId: user.id, email, purpose: "register" });
      await audit(user.id, "login", "requested", { stage: "verification_otp" });
      return res.status(202).json({ otp_required: true, purpose: "register", message: "A verification code has been sent.", email: maskEmail(email) });
    }
    await issueOtp({ userId: user.id, email, purpose: "login" });
    await audit(user.id, "login", "requested", { stage: "otp" });
    res.status(202).json({ otp_required: true, message: "A sign-in code has been sent.", email: maskEmail(email) });
  } catch (error) { next(error); }
});

router.post("/verify-otp", async (req, res, next) => {
  try {
    const input = parse(otpSchema, req, res); if (!input) return;
    const email = normalizeEmail(input.email);
    const emailDigest = digestEmail(email, config.otpSecret);
    const outcome = await withTransaction(async (client) => {
      const { rows } = await client.query(
        `SELECT o.*,u.id AS uid,u.name,u.email,u.role,u.is_verified FROM otp_codes o
         LEFT JOIN users u ON u.id=o.user_id
         WHERE o.email_digest=$1 AND o.purpose=$2 AND o.consumed_at IS NULL
         ORDER BY o.sent_at DESC LIMIT 1 FOR UPDATE OF o`, [emailDigest, input.purpose]
      );
      const row = rows[0];
      if (!row || new Date(row.expires_at) <= new Date() || (row.locked_until && new Date(row.locked_until) > new Date())) return { ok: false, reason: "invalid" };
      if (!safeEqual(row.code_hash, hashOtp(input.otp, config.otpSecret))) {
        const attempts = row.attempts + 1;
        await client.query("UPDATE otp_codes SET attempts=$2,locked_until=CASE WHEN $2>=5 THEN NOW()+INTERVAL '15 minutes' ELSE locked_until END WHERE id=$1", [row.id, attempts]);
        return { ok: false, reason: attempts >= 5 ? "locked" : "invalid", userId: row.user_id };
      }
      await client.query("UPDATE otp_codes SET consumed_at=NOW() WHERE id=$1", [row.id]);
      if (input.purpose === "register") await client.query("UPDATE users SET is_verified=TRUE,updated_at=NOW() WHERE id=$1", [row.uid]);
      if (input.purpose === "reset") return { ok: true, purpose: input.purpose, userId: row.uid };
      await client.query("DELETE FROM sessions WHERE user_id=$1", [row.uid]);
      await createSession(client, row.uid, res);
      return { ok: true, purpose: input.purpose, userId: row.uid, user: { id: row.uid, name: row.name, email: row.email, role: row.role } };
    });
    if (!outcome.ok) {
      await audit(outcome.userId, "otp_verified", "failure", { purpose: input.purpose, reason: outcome.reason });
      return res.status(400).json({ error: "That code is invalid or expired. Request a new one and try again." });
    }
    await audit(outcome.userId, "otp_verified", "success", { purpose: input.purpose });
    if (input.purpose === "reset") return res.json({ message: "Code verified. You can now reset your password." });
    if (input.purpose === "register") {
      try { await sendNotice({ to: outcome.user.email, name: outcome.user.name, type: "welcome" }); }
      catch { await audit(outcome.userId, "welcome_email", "failure"); }
    }
    res.json({ user: outcome.user });
  } catch (error) { next(error); }
});

router.post("/resend-otp", async (req, res, next) => {
  try {
    const input = parse(resendSchema, req, res); if (!input) return;
    const email = normalizeEmail(input.email);
    const { rows } = await pool.query("SELECT id FROM users WHERE email=$1 AND is_verified=($2 <> 'register')", [email, input.purpose]);
    const user = rows[0];
    if (user) {
      try { await issueOtp({ userId: user.id, email, purpose: input.purpose, isResend: true }); }
      catch { await audit(user.id, "otp_sent", "failure", { purpose: input.purpose }); }
    }
    res.status(202).json({ message: "If the request is eligible, a new code will be sent shortly." });
  } catch (error) { next(error); }
});

router.post("/forgot-password", async (req, res, next) => {
  try {
    const schema = z.object({ email: z.string().email().max(254) });
    const input = parse(schema, req, res); if (!input) return;
    const email = normalizeEmail(input.email);
    const { rows } = await pool.query("SELECT id FROM users WHERE email=$1 AND is_verified=TRUE", [email]);
    if (rows[0]) {
      try {
        await issueOtp({ userId: rows[0].id, email, purpose: "reset" });
        await audit(rows[0].id, "reset_requested", "requested");
      } catch { await audit(rows[0].id, "reset_requested", "failure"); }
    }
    res.status(202).json({ message: "If an account exists for that address, reset instructions are on their way.", email: maskEmail(email) });
  } catch (error) { next(error); }
});

router.post("/reset-password", async (req, res, next) => {
  try {
    const input = parse(resetSchema, req, res); if (!input) return;
    const email = normalizeEmail(input.email);
    const passwordHash = await hashPassword(input.newPassword);
    const result = await withTransaction(async (client) => {
      const emailDigest = digestEmail(email, config.otpSecret);
      const { rows } = await client.query(
        `SELECT o.id,u.id AS user_id,o.code_hash,o.expires_at,o.attempts,o.locked_until FROM otp_codes o JOIN users u ON u.id=o.user_id
         WHERE o.email_digest=$1 AND o.purpose='reset' AND o.consumed_at IS NULL ORDER BY o.sent_at DESC LIMIT 1 FOR UPDATE OF o`, [emailDigest]
      );
      const row = rows[0];
      if (!row || new Date(row.expires_at) <= new Date() || (row.locked_until && new Date(row.locked_until) > new Date())) return null;
      if (!safeEqual(row.code_hash, hashOtp(input.otp, config.otpSecret))) {
        const attempts = row.attempts + 1;
        await client.query("UPDATE otp_codes SET attempts=$2,locked_until=CASE WHEN $2>=5 THEN NOW()+INTERVAL '15 minutes' ELSE locked_until END WHERE id=$1", [row.id, attempts]);
        return null;
      }
      await client.query("UPDATE otp_codes SET consumed_at=NOW() WHERE id=$1", [row.id]);
      await client.query("UPDATE users SET password_hash=$2,updated_at=NOW() WHERE id=$1", [row.user_id, passwordHash]);
      await client.query("DELETE FROM sessions WHERE user_id=$1", [row.user_id]);
      await client.query("UPDATE reset_tokens SET consumed_at=NOW() WHERE user_id=$1 AND consumed_at IS NULL", [row.user_id]);
      return row.user_id;
    });
    if (!result) return res.status(400).json({ error: "That code is invalid or expired. Request a new one and try again." });
    await audit(result, "reset_done", "success");
    res.json({ message: "Password updated. Sign in with your new password." });
  } catch (error) { next(error); }
});

router.post("/logout", async (req, res, next) => {
  try {
    const token = await getSessionToken(req);
    if (token) {
      const { rows } = await pool.query("DELETE FROM sessions WHERE token_hash=$1 RETURNING user_id", [hashOpaqueToken(token)]);
      if (rows[0]) await audit(rows[0].user_id, "logout", "success");
    }
    res.clearCookie(COOKIE_NAME, { httpOnly: true, secure: config.secureCookies, sameSite: "lax", path: "/" });
    res.status(204).end();
  } catch (error) { next(error); }
});

router.get("/me", async (req, res) => {
  if (!req.authUser) return res.status(401).json({ error: "Authentication required." });
  res.json({ user: req.authUser });
});

router.patch("/users/:userId/role", async (req, res, next) => {
  try {
    if (!req.authUser) return res.status(401).json({ error: "Authentication required." });
    if (req.authUser.role !== "Admin") return res.status(403).json({ error: "You do not have permission to perform this action." });
    if (!z.string().uuid().safeParse(req.params.userId).success) return res.status(400).json({ error: "Check the provided information and try again." });
    const input = parse(roleSchema, req, res); if (!input) return;
    const { rows } = await pool.query("UPDATE users SET role=$2,updated_at=NOW() WHERE id=$1 RETURNING id", [req.params.userId, input.role]);
    if (!rows[0]) return res.status(404).json({ error: "User not found." });
    await audit(req.authUser.id, "role_change", "success", { targetUserId: rows[0].id, role: input.role });
    res.json({ message: "Role updated." });
  } catch (error) { next(error); }
});

export function authRouter() { return router; }
export { COOKIE_NAME, getSessionToken, config };

