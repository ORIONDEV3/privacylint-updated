import express from "express";
import helmet from "helmet";
import cors from "cors";
import cookieParser from "cookie-parser";
import { rateLimit } from "express-rate-limit";
import { authRouter, config, COOKIE_NAME } from "./auth.js";
import { isAllowedWebOrigin } from "./config.js";
import { pool } from "./db.js";
import { csrfToken, hashOpaqueToken, safeEqual, verifyCookie } from "./security.js";

export const app = express();
app.disable("x-powered-by");
app.set("trust proxy", config.nodeEnv === "production" ? 1 : false);
app.use(helmet({ crossOriginResourcePolicy: { policy: "same-site" }, referrerPolicy: { policy: "strict-origin-when-cross-origin" } }));
app.use(cors({
  origin(origin, callback) {
    if (!origin || isAllowedWebOrigin(origin, config)) return callback(null, true);
    return callback(Object.assign(new Error("Origin not allowed"), { status: 403 }));
  },
  credentials: true,
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "X-CSRF-Token"]
}));
app.use(express.json({ limit: "32kb", strict: true }));
app.use(cookieParser());

app.get("/health", (_req, res) => res.json(authHealth()));

app.use((req, res, next) => {
  if (!["GET", "HEAD", "OPTIONS"].includes(req.method)) {
    const origin = req.get("origin");
    if (!origin || !isAllowedWebOrigin(origin, config)) return res.status(403).json({ error: "Request origin is not allowed." });
  }
  next();
});

app.use(rateLimit({
  windowMs: 15 * 60 * 1000, limit: 120, standardHeaders: "draft-7", legacyHeaders: false,
  handler: (_req, res) => res.status(429).json({ error: "Too many requests. Please try again later." })
}));

app.use(async (req, _res, next) => {
  try {
    const signed = req.cookies?.[COOKIE_NAME];
    const token = verifyCookie(signed, config.sessionSecret);
    if (!token) return next();
    const { rows } = await pool.query(
      `SELECT u.id,u.name,u.email,u.role,s.id AS session_id FROM sessions s
       JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>NOW() AND u.is_verified=TRUE`,
      [hashOpaqueToken(token)]
    );
    if (rows[0]) {
      req.authUser = { id: rows[0].id, name: rows[0].name, email: rows[0].email, role: rows[0].role };
      req.sessionToken = token;
    }
    next();
  } catch (error) { next(error); }
});

app.use((req, res, next) => {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method) || !req.authUser) return next();
  const supplied = req.get("x-csrf-token") || "";
  const expected = csrfToken(req.sessionToken, config.csrfSecret);
  if (!safeEqual(supplied, expected)) return res.status(403).json({ error: "Your session token expired. Refresh and try again." });
  next();
});

export function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.authUser) return res.status(401).json({ error: "Authentication required." });
    if (!roles.includes(req.authUser.role)) return res.status(403).json({ error: "You do not have permission to perform this action." });
    next();
  };
}

export function authHealth() { return { status: "ok", service: "auth" }; }
app.use("/api/v1/auth", authRouter());
app.use((_req, res) => res.status(404).json({ error: "Not found." }));
app.use((error, _req, res, _next) => {
  // Deliberately omit exception text and request data; either can contain sensitive values.
  res.status(error.status || 500).json({ error: error.status ? error.message : "A server error occurred." });
});

