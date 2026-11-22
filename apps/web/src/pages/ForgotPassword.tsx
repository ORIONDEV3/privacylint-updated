import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { ArrowLeft, MailCheck } from "lucide-react";
import { get, post } from "../api";
import { TextField } from "../components/FormFields";
import Notice from "../components/Notice";
import SubmitButton from "../components/SubmitButton";

export default function ForgotPassword() {
  const [email, setEmail] = useState(""); const [error, setError] = useState(""); const [loading, setLoading] = useState(false); const [sent, setSent] = useState(false); const navigate = useNavigate();
  const [emailOtpEnabled, setEmailOtpEnabled] = useState(false);
  useEffect(() => { get<{ emailOtpEnabled: boolean }>("/api/v1/auth/config").then((status) => setEmailOtpEnabled(status.emailOtpEnabled)).catch(() => setEmailOtpEnabled(false)); }, []);
  async function submit(event: React.FormEvent) {
    event.preventDefault(); setError(""); setLoading(true);
    try { await post("/api/v1/auth/forgot-password", { email }); setSent(true); }
    catch (caught) { setError((caught as Error).message); }
    finally { setLoading(false); }
  }
  return <motion.div className="auth-card" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: .35 }}>
    <Link to="/login" className="back-link"><ArrowLeft size={15} /> Back to sign in</Link>
    {sent ? <div className="reset-sent"><span className="sent-icon"><MailCheck size={22} /></span><div className="form-kicker">CHECK YOUR EMAIL</div><h2>Instructions are on the way<span className="title-period">.</span></h2><p className="form-subtitle">If an account exists for that address, you’ll receive a one-time reset code. The code expires in 10 minutes.</p><button className="submit-button" type="button" onClick={() => navigate("/reset-password", { state: { email } })}>Enter reset code <span>→</span></button></div> : <>
      <div className="form-kicker"><span className="kicker-icon"><MailCheck size={16} /></span> ACCOUNT RECOVERY</div>
      <h2>Forgot password<span className="title-period">?</span></h2>
      {emailOtpEnabled ? <>
        <p className="form-subtitle">Enter the email tied to your account. We’ll send a secure reset code if it exists.</p>
        {error && <Notice message={error} />}
        <form onSubmit={submit} className="auth-form"><TextField label="Work email" name="email" type="email" autoComplete="email" placeholder="you@company.com" value={email} onChange={(e) => setEmail(e.target.value)} required /><SubmitButton loading={loading}>Send reset code</SubmitButton></form>
      </> : <p className="form-subtitle">Email password recovery is currently unavailable. Please contact your workspace administrator for a reset.</p>}
    </>}
    <p className="switch-form">Remember your password? <Link to="/login">Sign in <ArrowLeft size={13} /></Link></p>
  </motion.div>;
}

