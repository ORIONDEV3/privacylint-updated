import "dotenv/config";

const requiredInProduction = ["SESSION_SECRET", "OTP_HMAC_SECRET", "CSRF_SECRET"];

export function loadConfig(env = process.env) {
  if (env.NODE_ENV === "production") {
    for (const key of requiredInProduction) {
      if (!env[key] || env[key].length < 32) throw new Error(`${key} must contain at least 32 characters`);
    }
  }
  const origins = (env.WEB_ORIGIN || "http://localhost:5173,http://127.0.0.1:5173")
    .split(",").map((value) => value.trim()).filter(Boolean);
  const smtpUser = env.SMTP_USER || "";
  const smtpPass = env.SMTP_PASS || "";
  const otpMode = (env.AUTH_OTP_MODE || (env.NODE_ENV === "production" || (smtpUser && smtpPass) ? "email" : "password")).toLowerCase();
  if (!["email", "password"].includes(otpMode)) throw new Error("AUTH_OTP_MODE must be 'email' or 'password'");
  if (env.NODE_ENV === "production" && otpMode !== "email" && env.AUTH_ALLOW_PASSWORD_ONLY !== "true") {
    throw new Error("Password-only sign-in in production requires AUTH_ALLOW_PASSWORD_ONLY=true");
  }
  return Object.freeze({
    nodeEnv: env.NODE_ENV || "development",
    port: Number(env.AUTH_PORT || 4000),
    host: env.AUTH_HOST || "127.0.0.1",
    databaseUrl: env.DATABASE_URL || (env.NODE_ENV === "production" ? "" : "postgres://postgres:postgres@127.0.0.1:5433/postgres"),
    origins,
    otpMode,
    secureCookies: env.NODE_ENV === "production",
    bootstrapAdminEmail: (env.ADMIN_BOOTSTRAP_EMAIL || "").trim().toLowerCase(),
    sessionSecret: env.SESSION_SECRET || "development-session-secret-change-this-32-bytes",
    otpSecret: env.OTP_HMAC_SECRET || "development-otp-secret-change-this-32-bytes",
    csrfSecret: env.CSRF_SECRET || "development-csrf-secret-change-this-32-bytes",
    smtp: {
      host: env.SMTP_HOST || "localhost",
      port: Number(env.SMTP_PORT || 1025),
      user: smtpUser,
      pass: smtpPass,
      from: env.SMTP_FROM || "PrivacyLint <no-reply@privacylint.local>"
    },
    google: {
      clientId: env.GOOGLE_CLIENT_ID || "",
      clientSecret: env.GOOGLE_CLIENT_SECRET || "",
      redirectUri: env.GOOGLE_REDIRECT_URI || `http://localhost:${env.AUTH_PORT || 4000}/api/v1/auth/google/callback`,
      enabled: env.GOOGLE_OAUTH_ENABLED === "true"
    }
  });
}

export function isAllowedWebOrigin(origin, config = loadConfig()) {
  if (config.origins.includes(origin)) return true;
  // Vite selects the next free port when another local dev server already owns 5173.
  return config.nodeEnv !== "production" && /^https?:\/\/(localhost|127\.0\.0\.1):517[3-9]$/.test(origin);
}

