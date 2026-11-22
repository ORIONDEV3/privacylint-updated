import { ArrowRight, LoaderCircle } from "lucide-react";
import type { ReactNode } from "react";
export default function SubmitButton({ children, loading = false }: { children: ReactNode; loading?: boolean }) {
  return <button className="submit-button" type="submit" disabled={loading}>{loading ? <><LoaderCircle size={17} className="spin" /> Please wait</> : <>{children}<ArrowRight size={17} /></>}</button>;
}

