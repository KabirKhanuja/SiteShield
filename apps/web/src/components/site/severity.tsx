import { CheckCheckIcon, FileCodeIcon, GlobeIcon } from "lucide-react";
import { cn } from "@/lib/utils";

export type Severity = "critical" | "high" | "medium" | "low";
export type FindingStatus = "confirmed" | "code" | "live";

const severityClass: Record<Severity, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
};

export function SeverityLabel({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-1.5 text-xs font-medium capitalize", className)}>
      <span aria-hidden className={cn("size-2 rounded-[2px]", severityClass[severity])} />
      {severity}
    </span>
  );
}

const status: Record<FindingStatus, { label: string; icon: typeof CheckCheckIcon; className: string }> = {
  confirmed: { label: "Confirmed", icon: CheckCheckIcon, className: "font-medium text-primary-text" },
  code: { label: "Code only", icon: FileCodeIcon, className: "text-muted-foreground" },
  live: { label: "Live only", icon: GlobeIcon, className: "text-muted-foreground" },
};

// Plain icon and text, the way a code host marks review state, rather than a filled tag.
export function StatusLabel({ status: key }: { status: FindingStatus }) {
  const { label, icon: Icon, className } = status[key];
  return (
    <span className={cn("inline-flex items-center gap-1.5 pt-0.5 text-xs whitespace-nowrap", className)}>
      <Icon className="size-3.5" aria-hidden />
      {label}
    </span>
  );
}
