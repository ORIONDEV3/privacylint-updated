import { AlertCircle, CheckCircle2 } from "lucide-react";
export default function Notice({ message, success = false }: { message: string; success?: boolean }) {
  return <div className={`notice ${success ? "notice-success" : "notice-error"}`} role={success ? "status" : "alert"}>{success ? <CheckCircle2 size={16} /> : <AlertCircle size={16} />}<span>{message}</span></div>;
}

