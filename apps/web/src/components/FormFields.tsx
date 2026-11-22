import { useState, type InputHTMLAttributes } from "react";
import { Eye, EyeOff } from "lucide-react";

type InputProps = InputHTMLAttributes<HTMLInputElement> & { label: string; hint?: string };
export function TextField({ label, hint, id, ...props }: InputProps) {
  const fieldId = id || props.name || label.toLowerCase().replaceAll(" ", "-");
  return <div className="field"><label htmlFor={fieldId}>{label}</label><input id={fieldId} {...props} /><span className="field-hint">{hint}</span></div>;
}

export function PasswordField({ label = "Password", id = "password", ...props }: Omit<InputProps, "type">) {
  const [visible, setVisible] = useState(false);
  return <div className="field"><label htmlFor={id}>{label}</label><div className="password-wrap"><input id={id} type={visible ? "text" : "password"} autoComplete="current-password" {...props} /><button className="icon-button password-toggle" type="button" onClick={() => setVisible(!visible)} aria-label={visible ? "Hide password" : "Show password"}>{visible ? <EyeOff size={17} /> : <Eye size={17} />}</button></div></div>;
}

export function PasswordStrength({ password }: { password: string }) {
  const checks = [password.length >= 12, /[A-Z]/.test(password) && /[a-z]/.test(password), /\d/.test(password), /[^A-Za-z0-9]/.test(password)];
  const score = checks.filter(Boolean).length;
  const text = password.length === 0 ? "Use at least 12 characters" : ["Add more variety", "Could be stronger", "Good strength", "Strong password", "Excellent password"][score];
  return <div className="strength" aria-live="polite"><div className="strength-bars">{checks.map((active, i) => <span key={i} className={active ? `active strength-${score}` : ""} />)}</div><span>{text}</span></div>;
}

