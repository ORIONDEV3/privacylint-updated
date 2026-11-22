import { useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { ArrowLeft, KeyRound } from "lucide-react";
import { post } from "../api";
import { PasswordField, PasswordStrength, TextField } from "../components/FormFields";
import Notice from "../components/Notice";
import SubmitButton from "../components/SubmitButton";

export default function ResetPassword() {
  const location = useLocation(); const navigate = useNavigate(); const email = (location.state as { email?: string } | null)?.email || "";
  const [otp, setOtp] = useState(""); const [password, setPassword] = useState(""); const [confirm, setConfirm] = useState("");
  const [error, setError] = useState(""); const [loading, setLoading] = useState(false); const [done, setDone] = useState(false);
  async function submit(event: React.FormEvent) {
    event.preventDefault(); setError("");
    if (password !== confirm) { setError("Those passwords don’t match."); return; }
    setLoading(true);
    try { await post("/api/v1/auth/reset-password", { email, otp, newPassword: password }); setDone(true); }
    catch (caught) { setError((caught as Error).message); }
    finally { setLoading(false); }
  }
  return <motion.div className="auth-card" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: .35 }}>
    <Link to="/login" className="back-link"><ArrowLeft size={15} /> Back to sign in</Link>
    {done ? <div className="reset-sent"><span className="sent-icon"><KeyRound size={21} /></span><div className="form-kicker">PASSWORD UPDATED</div><h2>You’re back in control<span className="title-period">.</span></h2><p className="form-subtitle">Your password has been updated and existing sessions were signed out.</p><Link className="submit-button link-button" to="/login">Return to sign in <span>→</span></Link></div> : <>
      <div className="form-kicker"><span className="kicker-icon"><KeyRound size={16} /></span> SECURE RECOVERY</div>
      <h2>Set a new password<span className="title-period">.</span></h2>
      <p className="form-subtitle">Enter the 6-digit code from your email and choose a new password.</p>
      {!email && <Notice message="Start from Forgot password so we know where to send the code." />}
      {error && <Notice message={error} />}
      <form onSubmit={submit} className="auth-form">
        <TextField label="6-digit reset code" name="otp" inputMode="numeric" autoComplete="one-time-code" placeholder="000000" value={otp} onChange={(e) => setOtp(e.target.value.replace(/\D/g, "").slice(0, 6))} pattern="[0-9]{6}" required />
        <PasswordField label="New password" id="new-password" name="newPassword" autoComplete="new-password" placeholder="At least 12 characters" value={password} onChange={(e) => setPassword(e.target.value)} minLength={12} maxLength={128} required />
        <PasswordStrength password={password} />
        <PasswordField label="Confirm new password" id="confirm-password" name="confirmPassword" autoComplete="new-password" placeholder="Re-enter your password" value={confirm} onChange={(e) => setConfirm(e.target.value)} minLength={12} required />
        <button className="submit-button" type="submit" disabled={loading || !email}>{loading ? "Updating…" : <>Update password <span>→</span></>}</button>
      </form>
    </>}
  </motion.div>;
}

