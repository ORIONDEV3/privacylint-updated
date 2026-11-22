import { createContext, useMemo, useState } from "react";
import { Link, Navigate, NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import type { LucideIcon } from "lucide-react";
import {
  Activity, ArrowUpRight, BadgeCheck, Bell, BookOpenCheck, Boxes, ChevronDown, ChevronLeft,
  CircleHelp, FileCode2, FileText, GitPullRequest, LayoutDashboard, LockKeyhole, LogOut,
  Menu, Moon, Network, ScanLine, Search, Settings, Shield, ShieldCheck, Sun, X,
} from "lucide-react";
import { get, post } from "../api";

type User = { id: string; name: string; email: string; role: string };
type WorkspaceValue = { aiEnabled: boolean; setAiEnabled: (enabled: boolean) => void; lightMode: boolean };
export const WorkspaceContext = createContext<WorkspaceValue>({ aiEnabled: false, setAiEnabled: () => undefined, lightMode: false });

type NavItem = { to: string; label: string; icon: LucideIcon; accent?: boolean; soon?: boolean };
const navigation: Array<{ label: string; items: NavItem[] }> = [
  { label: "WORKSPACE", items: [
    { to: "/workspace/overview", label: "Overview", icon: LayoutDashboard },
    { to: "/workspace/scans/new", label: "New scan", icon: ScanLine, accent: true },
    { to: "/workspace/scans", label: "Scan history", icon: Activity },
    { to: "/workspace/findings", label: "Findings", icon: Shield },
  ] },
  { label: "REMEDIATE", items: [
    { to: "/workspace/lineage", label: "Data lineage", icon: Network },
    { to: "/workspace/fixes", label: "Fix workflow", icon: FileCode2 },
    { to: "/workspace/tests", label: "Regression tests", icon: BookOpenCheck },
    { to: "/workspace/pr", label: "PR automation", icon: GitPullRequest },
  ] },
  { label: "GOVERNANCE", items: [
    { to: "/workspace/reports", label: "Reports", icon: FileText },
    { to: "/workspace/badge", label: "Privacy badge", icon: BadgeCheck },
    { to: "/workspace/security", label: "Security center", icon: LockKeyhole },
    { to: "/workspace/rules", label: "Rules", icon: Boxes },
  ] },
];

const titles: Record<string, string> = {
  "/workspace/overview": "Overview", "/workspace/scans/new": "New scan", "/workspace/scans": "Scan history",
  "/workspace/findings": "Findings", "/workspace/lineage": "Data lineage", "/workspace/fixes": "Fix workflow",
  "/workspace/tests": "Regression tests", "/workspace/pr": "PR automation", "/workspace/reports": "Reports",
  "/workspace/badge": "Privacy badge", "/workspace/security": "Security center", "/workspace/rules": "Rule configuration",
  "/workspace/settings": "Settings",
};

export default function Workspace() {
  const navigate = useNavigate(); const location = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false); const [userMenuOpen, setUserMenuOpen] = useState(false);
  const [lightMode, setLightMode] = useState(() => window.localStorage.getItem("pl_theme") === "light");
  const [aiEnabled, setAiEnabled] = useState(() => window.sessionStorage.getItem("pl_ai_enabled") === "true");
  const query = useQuery({ queryKey: ["me"], queryFn: () => get<{ user: User }>("/api/v1/auth/me"), retry: false });
  const currentTitle = useMemo(() => titles[location.pathname] || (location.pathname.includes("/scans/") ? "Scan detail" : "Privacy workspace"), [location.pathname]);
  if (query.isLoading) return <main className="workspace-loading"><div className="loading-mark"><ShieldCheck /></div><p>Opening your private workspace…</p></main>;
  if (query.isError || !query.data) return <Navigate to="/login" replace />;
  const user = query.data.user;
  function changeTheme() { setLightMode((old) => { const next = !old; window.localStorage.setItem("pl_theme", next ? "light" : "dark"); return next; }); }
  function changeAi(value: boolean) { setAiEnabled(value); window.sessionStorage.setItem("pl_ai_enabled", String(value)); }
  async function logout() { try { await post("/api/v1/auth/logout", {}, true); navigate("/login", { replace: true }); } catch { setUserMenuOpen(false); } }
  const initials = user.name.trim().split(/\s+/).slice(0, 2).map((word) => word[0]).join("").toUpperCase();

  return <WorkspaceContext.Provider value={{ aiEnabled, setAiEnabled: changeAi, lightMode }}>
    <div className={`console-shell${lightMode ? " light-mode" : ""}`}>
      <button className={`mobile-backdrop${sidebarOpen ? " visible" : ""}`} aria-label="Close navigation" onClick={() => setSidebarOpen(false)} />
      <aside className={`console-sidebar${sidebarOpen ? " sidebar-open" : ""}`}>
        <div className="sidebar-brand-row"><Link className="brand-lockup" to="/workspace/overview"><span className="brand-mark"><ShieldCheck size={18} /></span><span>Privacy<span className="brand-lint">Lint</span></span></Link><button className="sidebar-collapse" aria-label="Close navigation" onClick={() => setSidebarOpen(false)}><X size={16} /></button></div>
        <button className="workspace-switcher"><span className="workspace-switch-icon"><ShieldCheck size={14} /></span><span><b>Personal workspace</b><small>Free plan · local mode</small></span><ChevronDown size={14} /></button>
        <nav className="sidebar-nav" aria-label="Workspace navigation">
          {navigation.map((group) => <section className="nav-group" key={group.label}><div className="nav-group-label">{group.label}</div>{group.items.map((item) => {
            const Icon = item.icon; return <NavLink key={item.to} to={item.to} onClick={() => setSidebarOpen(false)} className={({ isActive }) => `nav-link${isActive ? " active" : ""}${item.accent ? " nav-accent" : ""}`}><Icon size={16} /><span>{item.label}</span>{item.soon && <em>SOON</em>}{item.accent && <ArrowUpRight size={13} className="nav-trailing" />}</NavLink>;
          })}</section>)}
        </nav>
        <div className="sidebar-spacer" />
        <div className="sidebar-status"><span className="status-dot" /><span>Local analysis ready</span><span className="status-version">v0.2</span></div>
        <NavLink to="/workspace/settings" className={({ isActive }) => `nav-link settings-link${isActive ? " active" : ""}`}><Settings size={16} /><span>Settings</span></NavLink>
        <div className="sidebar-footer"><span className="footer-lock"><LockKeyhole size={14} /></span><span>Code stays in your workspace.<br /><b>Private by design.</b></span><CircleHelp size={15} className="footer-help" /></div>
      </aside>

      <section className="console-main">
        <header className="console-topbar">
          <div className="topbar-left"><button className="mobile-menu" aria-label="Open navigation" onClick={() => setSidebarOpen(true)}><Menu size={19} /></button><div className="breadcrumbs"><span>Workspace</span><b>/</b><strong>{currentTitle}</strong></div></div>
          <form className="global-search" onSubmit={(event) => { event.preventDefault(); const data = new FormData(event.currentTarget); navigate(`/workspace/scans?q=${encodeURIComponent(String(data.get("q") || ""))}`); }}><Search size={15} /><input name="q" placeholder="Search scans, findings…" aria-label="Search scans and findings" /><kbd>Ctrl K</kbd></form>
          <div className="topbar-actions"><button className={`ai-toggle${aiEnabled ? " ai-on" : ""}`} aria-pressed={aiEnabled} onClick={() => changeAi(!aiEnabled)} title={aiEnabled ? "Gemini fixer enabled when configured" : "Offline deterministic fixes only"}><span className="ai-spark">✳</span><span>AI</span><span className="toggle-track"><i /></span><b>{aiEnabled ? "ON" : "OFF"}</b></button><button className="topbar-icon" aria-label={lightMode ? "Switch to dark theme" : "Switch to light theme"} onClick={changeTheme}>{lightMode ? <Moon size={16} /> : <Sun size={16} />}</button><button className="topbar-icon notification-button" aria-label="Notifications"><Bell size={16} /><i /></button><div className="user-menu-wrap"><button className="user-trigger" aria-expanded={userMenuOpen} onClick={() => setUserMenuOpen(!userMenuOpen)}><span className="user-avatar">{initials || "PL"}</span><span className="user-name-mini">{user.name.split(" ")[0]}</span><ChevronDown size={13} /></button>{userMenuOpen && <div className="user-menu"><div className="user-menu-id"><b>{user.name}</b><span>{user.email}</span><small>{user.role}</small></div><button onClick={() => navigate("/workspace/settings")}><Settings size={14} /> Settings</button><button onClick={logout}><LogOut size={14} /> Sign out</button></div>}</div></div>
        </header>
        <main className="console-page"><Outlet /></main>
      </section>
    </div>
  </WorkspaceContext.Provider>;
}
