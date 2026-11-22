import { useEffect, useRef, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { ArrowLeft, Check } from "lucide-react";
import { post } from "../api";
import Notice from "../components/Notice";
import SubmitButton from "../components/SubmitButton";

type VerifyState = { email?: string; maskedEmail?: string; purpose?: "register" | "login" };
export default function VerifyOtp() {
  const location = useLocation(); const navigate = useNavigate(); const state = (location.state || {}) as VerifyState;
  const [digits, setDigits] = useState(["", "", "", "", "", ""]); const [seconds, setSeconds] = useState(60);
  const [error, setError] = useState(""); const [loading, setLoading] = useState(false); const [verified, setVerified] = useState(false);
  const inputs = useRef<Array<HTMLInputElement | null>>([]);
  useEffect(() => { const timer = window.setInterval(() => setSeconds((value) => Math.max(0, value - 1)), 1000); return () => window.clearInterval(timer); }, []);
  if (!state.email || !state.purpose) return <div className="auth-card"><h2>Verification link expired<span className="title-period">.</span></h2><p className="form-subtitle">Return to sign in or create your account to request a fresh code.</p><Link className="submit-button link-button" to="/login">Back to sign in</Link></div>;
  const otp = digits.join("");
  function change(index: number, value: string) {
    const clean = value.replace(/\D/g, "");
    if (clean.length > 1) {
      const chars = clean.slice(0, 6).split(""); setDigits(Array.from({ length: 6 }, (_, i) => chars[i] || "")); inputs.current[Math.min(chars.length, 5)]?.focus(); return;
    }
    setDigits((old) => old.map((digit, i) => i === index ? clean : digit));
    if (clean && index < 5) inputs.current[index + 1]?.focus();
  }
  function keyDown(index: number, event: React.KeyboardEvent<HTMLInputElement>) {
    if (event.key === "Backspace" && !digits[index] && index > 0) inputs.current[index - 1]?.focus();
    if (event.key === "ArrowLeft" && index > 0) inputs.current[index - 1]?.focus();
    if (event.key === "ArrowRight" && index < 5) inputs.current[index + 1]?.focus();
  }
  async function submit(event: React.FormEvent) {
    event.preventDefault(); setError(""); setLoading(true);
    try {
      await post("/api/v1/auth/verify-otp", { email: state.email, otp, purpose: state.purpose });
      setVerified(true); window.setTimeout(() => navigate("/workspace", { replace: true }), 900);
    } catch (caught) { setError((caught as Error).message); setDigits(["", "", "", "", "", ""]); inputs.current[0]?.focus(); }
    finally { setLoading(false); }
  }
  async function resend() {
    setError(""); setLoading(true);
    try { await post("/api/v1/auth/resend-otp", { email: state.email, purpose: state.purpose }); setSeconds(60); setDigits(["", "", "", "", "", ""]); }
    catch (caught) { setError((caught as Error).message); }
    finally { setLoading(false); }
  }
  return <motion.div className="auth-card otp-card" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: .35 }}>
    {verified ? <div className="verified-state"><motion.div className="verified-check" initial={{ scale: .6 }} animate={{ scale: 1 }}><Check size={28} /></motion.div><h2>{state.purpose === "register" ? "Email verified" : "You're signed in"}<span className="title-period">.</span></h2><p className="form-subtitle">Opening your secure workspace…</p></div> : <>
      <Link to={state.purpose === "register" ? "/register" : "/login"} className="back-link"><ArrowLeft size={15} /> Back</Link>
      <div className="form-kicker"><span className="kicker-icon"><span className="otp-icon">•••</span></span> TWO-STEP VERIFICATION</div>
      <h2>Check your inbox<span className="title-period">.</span></h2>
      <p className="form-subtitle">We sent a 6-digit code to <strong className="masked-email">{state.maskedEmail || "your email"}</strong></p>
      {error && <Notice message={error} />}
      <form onSubmit={submit} className="auth-form">
        <div className="otp-inputs" role="group" aria-label="Six digit verification code">
          {digits.map((digit, index) => <input key={index} ref={(element) => { inputs.current[index] = element; }} aria-label={`Digit ${index + 1}`} inputMode="numeric" autoComplete={index === 0 ? "one-time-code" : "off"} maxLength={1} value={digit} onChange={(e) => change(index, e.target.value)} onKeyDown={(e) => keyDown(index, e)} onPaste={(e) => { e.preventDefault(); change(index, e.clipboardData.getData("text")); }} className={digit ? "filled" : ""} />)}
        </div>
        <div className="otp-caption"><span>6 digits · Expires in 10 minutes</span><span>00:{String(seconds).padStart(2, "0")}</span></div>
        <SubmitButton loading={loading || otp.length !== 6}>Verify and continue</SubmitButton>
      </form>
      <p className="resend-copy">Didn’t receive the code? {seconds > 0 ? <span>Resend in <b>00:{String(seconds).padStart(2, "0")}</b></span> : <button className="text-button" onClick={resend} disabled={loading}>Resend code</button>}</p>
    </>}
  </motion.div>;
}

