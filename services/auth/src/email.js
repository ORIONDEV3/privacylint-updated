import nodemailer from "nodemailer";
import { loadConfig } from "./config.js";

const config = loadConfig();
const smtpPass = config.smtp.pass.replace(/\s+/g, "");
const transport = nodemailer.createTransport({
  host: config.smtp.host, port: config.smtp.port,
  secure: config.smtp.port === 465,
  ...(config.smtp.user ? { auth: { user: config.smtp.user, pass: smtpPass } } : {}),
  connectionTimeout: 5000, greetingTimeout: 5000, socketTimeout: 10000
});

function safeSmtpError(error) {
  return {
    code: error?.code || null,
    responseCode: error?.responseCode || null,
    command: error?.command || null
  };
}

if (config.otpMode === "email" && config.smtp.user && smtpPass) {
  transport.verify()
    .then(() => console.info("PrivacyLint SMTP transport verified"))
    .catch((error) => console.error("PrivacyLint SMTP verification failed", safeSmtpError(error)));
}

const templates = {
  register: { subject: "Verify your PrivacyLint account", title: "Confirm your email", intro: "Use this one-time code to finish creating your PrivacyLint account." },
  login: { subject: "Your PrivacyLint sign-in code", title: "Your sign-in code", intro: "Enter this code to securely finish signing in." },
  reset: { subject: "Reset your PrivacyLint password", title: "Reset your password", intro: "Use this one-time code to choose a new password." }
};

const noticeTemplates = {
  welcome: { subject: "Welcome to PrivacyLint", title: "Your privacy workspace is ready", intro: "Your account is verified. You can now securely sign in and prepare your first repository scan." },
  scanComplete: { subject: "Your PrivacyLint scan is complete", title: "Scan complete", intro: "Your repository scan has finished. Sign in to review the findings, evidence, and DPDP mappings." },
  prOpened: { subject: "A PrivacyLint fix pull request is ready", title: "Pull request ready", intro: "Verified privacy fixes and regression tests are ready for your review." }
};

let mailQueue = Promise.resolve();

function escapeHtml(value) { return String(value).replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]); }

function deliver({ to, subject, title, intro, otp, name }) {
  const safeName = name ? `<p style="color:#d7e1e8">Hi ${escapeHtml(name)},</p>` : "";
  const code = otp ? `<div style="background:#0b0f14;border:1px solid #263746;border-radius:12px;padding:18px;text-align:center;color:#2dd4bf;font:700 30px ui-monospace,monospace;letter-spacing:.28em">${otp}</div>` : "";
  const expiry = otp ? "<p style=\"font-size:13px;color:#9ca3af;margin-top:20px\">This code expires in 10 minutes. If you didn't request it, you can ignore this email.</p>" : "";
  const text = `${title}\n\n${name ? `Hi ${name},\n\n` : ""}${intro}${otp ? `\n\nYour code: ${otp}\n\nIt expires in 10 minutes. If you didn't request it, ignore this message.` : ""}`;
  return enqueue(async () => retry(async () => transport.sendMail({
    from: config.smtp.from, to, subject,
    html: `<!doctype html><html><body style="margin:0;background:#0b0f14;color:#e5e7eb;font-family:Inter,Arial,sans-serif;padding:36px 16px"><main style="max-width:520px;margin:auto;background:#121821;border:1px solid #1f2937;border-radius:16px;padding:32px"><div style="color:#2dd4bf;font-size:14px;font-weight:700;letter-spacing:.08em">PRIVACYLINT</div>${safeName}<h1 style="font-size:24px;margin:26px 0 10px">${title}</h1><p style="color:#9ca3af;line-height:1.6">${intro}</p>${code}${expiry}</main></body></html>`, text
  })));
}

function enqueue(job) {
  const result = mailQueue.then(job, job);
  mailQueue = result.catch(() => undefined);
  return result;
}

async function retry(job) {
  let error;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      return await job();
    } catch (caught) {
      error = caught;
      if (attempt < 2) await new Promise((resolve) => setTimeout(resolve, 300 * (2 ** attempt)));
    }
  }
  throw error;
}

export async function sendOtp({ to, otp, purpose }) {
  const copy = templates[purpose];
  if (!copy) throw new Error("Unsupported email template");
  return deliver({ to, otp, ...copy });
}

export async function sendNotice({ to, name = "", type }) {
  const copy = noticeTemplates[type];
  if (!copy) throw new Error("Unsupported email template");
  return deliver({ to, name, ...copy });
}

