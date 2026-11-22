import { useEffect, useState } from "react";
import { Outlet, useLocation } from "react-router-dom";
import { Moon, Sun } from "lucide-react";
import { BrandPanel } from "./BrandPanel";

export default function AuthLayout() {
  const location = useLocation();
  const [light, setLight] = useState(() => localStorage.getItem("pl-theme") === "light");
  useEffect(() => { document.documentElement.dataset.theme = light ? "light" : "dark"; localStorage.setItem("pl-theme", light ? "light" : "dark"); }, [light]);
  return <main className={`auth-shell ${light ? "light-mode" : ""}`} key={location.pathname}>
    <BrandPanel />
    <section className="auth-main">
      <button className="theme-toggle" type="button" aria-label={`Switch to ${light ? "dark" : "light"} mode`} onClick={() => setLight(!light)}>{light ? <Moon size={17} /> : <Sun size={17} />}<span>{light ? "Dark" : "Light"} mode</span></button>
      <div className="auth-mobile-brand"><span className="brand-mark">◈</span><span>Privacy<span className="brand-lint">Lint</span></span></div>
      <div className="form-wrap"><Outlet /></div>
      <footer className="auth-footer"><span>© 2026 PrivacyLint · CODECHAKRA</span><span><i className="status-dot" /> All systems protected</span></footer>
    </section>
  </main>;
}

