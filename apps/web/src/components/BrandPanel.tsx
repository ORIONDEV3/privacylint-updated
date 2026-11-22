import { motion } from "framer-motion";
import { ShieldCheck, ArrowDown, LockKeyhole, CircleCheck } from "lucide-react";

const stages = [
  { icon: "ID", label: "Aadhaar", value: "**** **** 4821", tone: "risk" },
  { icon: "↗", label: "API route", value: "/v1/signup", tone: "risk" },
  { icon: "▤", label: "Database", value: "users.aadhaar", tone: "risk" },
  { icon: "≋", label: "Logger", value: "console.log()", tone: "risk" }
];

export function BrandPanel() {
  return <aside className="brand-panel">
    <div className="brand-top"><a className="brand-lockup" href="/login"><span className="brand-mark"><ShieldCheck size={19} strokeWidth={2.3} /></span><span>Privacy<span className="brand-lint">Lint</span></span></a><span className="brand-pill"><span className="pulse-dot" /> PRIVACY ENGINE</span></div>
    <div className="brand-content">
      <div className="eyebrow"><span className="eyebrow-line" /> CODE WITH CONFIDENCE</div>
      <h1>Find the leak<br />before it becomes<br /><em>a breach.</em></h1>
      <p className="brand-copy">Trace personal data through your codebase, understand your DPDP exposure, and fix the flows that put trust at risk.</p>
      <div className="flow-card" aria-label="Animated data flow from Aadhaar through API and database to logger">
        <div className="flow-card-head"><span>LIVE DATA FLOW</span><span className="flow-scan">SCAN PREVIEW <span>01</span></span></div>
        <div className="flow-nodes">
          {stages.map((stage, index) => <div className="flow-unit" key={stage.label}>
            <motion.div className={`flow-node ${stage.tone}`} animate={{ borderColor: ["#47272e", "#263a3b", "#1f766f"], boxShadow: ["0 0 0 rgba(248,113,113,0)", "0 0 18px rgba(45,212,191,.08)", "0 0 18px rgba(45,212,191,.14)"] }} transition={{ duration: 4, repeat: Infinity, delay: index * .26 }}>
              <span className="node-symbol">{stage.icon}</span><span className="node-copy"><strong>{stage.label}</strong><small>{stage.value}</small></span>
              {index === stages.length - 1 ? <CircleCheck size={15} className="node-ok" /> : <ArrowDown size={14} className="node-arrow" />}
            </motion.div>
            {index < stages.length - 1 && <div className="flow-connector"><i /></div>}
          </div>)}
        </div>
        <div className="flow-card-foot"><span className="risk-chip"><span /> LEAK DETECTED</span><span className="flow-path">4 nodes <b>·</b> 3 exposed edges</span></div>
      </div>
      <div className="brand-proof"><span><LockKeyhole size={14} /> Private by design</span><span className="proof-separator" /><span>Built for India’s DPDP Act</span></div>
    </div>
    <div className="brand-bottom"><span>CODECHAKRA <b>×</b> hackFront India</span><span>SECURITY THAT SEES THE WHOLE FLOW</span></div>
    <div className="mesh mesh-one" /><div className="mesh mesh-two" />
  </aside>;
}

