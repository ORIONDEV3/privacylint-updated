import { useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { ArrowUpRight, Fingerprint } from "lucide-react";
import { AUTH_API, get, post } from "../api";
import { PasswordField, TextField } from "../components/FormFields";
import Notice from "../components/Notice";
import SubmitButton from "../components/SubmitButton";
import { motion } from "framer-motion";

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [emailOtpEnabled, setEmailOtpEnabled] = useState(false);
  const [googleEnabled, setGoogleEnabled] = useState(false);
  const [googleSetupRequired, setGoogleSetupRequired] = useState(false);
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  useEffect(() => { get<{ emailOtpEnabled: boolean; googleEnabled: boolean; googleSetupRequired: boolean }>("/api/v1/auth/config").then((status) => { setEmailOtpEnabled(status.emailOtpEnabled); setGoogleEnabled(status.googleEnabled); setGoogleSetupRequired(status.googleSetupRequired); }).catch(() => { setEmailOtpEnabled(false); setGoogleEnabled(false); }); }, []);
  const authError = searchParams.get("auth_error");
  async function submit(event: React.FormEvent) {
    event.preventDefault(); setError(""); setLoading(true);
    try {
      const result = await post<{ email?: string; otp_required: boolean; purpose?: "register" | "login" }>("/api/v1/auth/login", { email, password });
      if (result.otp_required) navigate("/verify", { state: { email, maskedEmail: result.email, purpose: result.purpose || "login" } });
      else navigate("/workspace/overview", { replace: true });
    } catch (caught) { setError((caught as Error).message); }
    finally { setLoading(false); }
  }
  return <motion.div className="auth-card" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: .35 }}>
    <div className="form-kicker"><span className="kicker-icon"><Fingerprint size={16} /></span> SECURE ACCESS</div>
    <h2>Welcome back<span className="title-period">.</span></h2>
    <p className="form-subtitle">Sign in to your privacy workspace.</p>
    {(error || authError) && <Notice message={error || (authError === "google_account_missing" ? "No account is linked to this Google email yet. Create an account with email and password first." : "Google sign-in could not be completed. Check the OAuth callback settings and try again.")} />}
    <form onSubmit={submit} className="auth-form">
      <TextField label="Work email" name="email" type="email" autoComplete="email" placeholder="you@company.com" value={email} onChange={(e) => setEmail(e.target.value)} required />
      <div className="field-label-row"><label htmlFor="password">Password</label><Link className="inline-link" to="/forgot-password">Forgot password?</Link></div>
      <PasswordField label="" id="password" name="password" placeholder="Enter your password" value={password} onChange={(e) => setPassword(e.target.value)} required />
      <div className="secure-note"><span className="tiny-lock" /> {emailOtpEnabled ? "A sign-in code will be sent to your email after password check" : "Email codes are off; sign in with your password"}</div>
      <SubmitButton loading={loading}>Continue securely</SubmitButton>
    </form>
    <div className="form-divider"><span /> or <span /></div>
    <button className="google-button" type="button" disabled={!googleEnabled} onClick={() => window.location.assign(`${AUTH_API}/api/v1/auth/google`)} title={!googleEnabled ? "Google OAuth needs a registered callback URL" : "Sign in with your verified Google account"}><span className="google-g">G</span><span>Continue with Google</span>{!googleEnabled && <span className="coming-soon">{googleSetupRequired ? "SETUP REQUIRED" : "NOT CONFIGURED"}</span>}</button>
    <p className="switch-form">New to PrivacyLint? <Link to="/register">Create an account <ArrowUpRight size={14} /></Link></p>
  </motion.div>;
}

