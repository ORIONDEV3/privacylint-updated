import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ArrowUpRight, ShieldCheck } from "lucide-react";
import { motion } from "framer-motion";
import { post } from "../api";
import { PasswordField, PasswordStrength, TextField } from "../components/FormFields";
import Notice from "../components/Notice";
import SubmitButton from "../components/SubmitButton";

export default function Register() {
  const [name, setName] = useState(""); const [email, setEmail] = useState(""); const [password, setPassword] = useState("");
  const [error, setError] = useState(""); const [loading, setLoading] = useState(false); const navigate = useNavigate();
  async function submit(event: React.FormEvent) {
    event.preventDefault(); setError(""); setLoading(true);
    try {
      const result = await post<{ email?: string; otp_required: boolean }>("/api/v1/auth/register", { name, email, password });
      if (result.otp_required) navigate("/verify", { state: { email, maskedEmail: result.email, purpose: "register" } });
      else navigate("/workspace/overview", { replace: true });
    } catch (caught) { setError((caught as Error).message); }
    finally { setLoading(false); }
  }
  return <motion.div className="auth-card" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: .35 }}>
    <div className="form-kicker"><span className="kicker-icon"><ShieldCheck size={16} /></span> START SECURE</div>
    <h2>Create your account<span className="title-period">.</span></h2>
    <p className="form-subtitle">Your first step toward privacy you can prove.</p>
    {error && <Notice message={error} />}
    <form onSubmit={submit} className="auth-form">
      <TextField label="Full name" name="name" autoComplete="name" placeholder="e.g. Neha Sharma" value={name} onChange={(e) => setName(e.target.value)} minLength={2} maxLength={100} required />
      <TextField label="Work email" name="email" type="email" autoComplete="email" placeholder="you@company.com" value={email} onChange={(e) => setEmail(e.target.value)} required />
      <PasswordField label="Create password" id="password" name="password" autoComplete="new-password" placeholder="At least 12 characters" value={password} onChange={(e) => setPassword(e.target.value)} minLength={12} maxLength={128} required />
      <PasswordStrength password={password} />
      <label className="consent-check"><input type="checkbox" required /><span>I agree to the <a href="#terms" onClick={(e) => e.preventDefault()}>Terms of Service</a> and <a href="#privacy" onClick={(e) => e.preventDefault()}>Privacy Policy</a>.</span></label>
      <SubmitButton loading={loading}>Create secure account</SubmitButton>
    </form>
    <p className="switch-form">Already have an account? <Link to="/login">Sign in <ArrowUpRight size={14} /></Link></p>
  </motion.div>;
}

