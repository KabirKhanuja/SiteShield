import { GradeTile } from "@/components/site/grade";
import { SeverityLabel, StatusLabel, type FindingStatus, type Severity } from "@/components/site/severity";

type SampleFinding = {
  severity: Severity;
  ids: string;
  title: string;
  status: FindingStatus;
  note?: string;
};

const findings: SampleFinding[] = [
  {
    severity: "critical",
    ids: "SEC001 + BND001",
    title: "Stripe secret key is inside the JavaScript sent to browsers",
    status: "confirmed",
  },
  {
    severity: "high",
    ids: "COR002 + COR001",
    title: "Any website can call /api/me with a signed in user's cookies",
    status: "confirmed",
  },
  {
    severity: "high",
    ids: "RTL002",
    title: "/api/auth/login has no rate limiter",
    status: "code",
    note: "Live test skipped until you verify ownership",
  },
  {
    severity: "medium",
    ids: "HDR001",
    title: "No Content Security Policy",
    status: "live",
  },
  {
    severity: "low",
    ids: "DNS001",
    title: "DMARC policy is p=none, so spoofed mail still gets delivered",
    status: "live",
  },
];

export function ReportPreview() {
  return (
    <figure className="overflow-hidden rounded-xl border bg-surface-low">
      <div className="flex items-center justify-between border-b px-4 py-3 text-xs">
        <span className="font-mono text-muted-foreground">shop.example.com</span>
        <span className="text-muted-foreground">Sample report</span>
      </div>

      <div className="grid grid-cols-[auto_1fr] items-center gap-5 border-b px-4 py-5">
        <GradeTile grade="C" className="size-18 text-5xl" />
        <dl className="grid grid-cols-3 gap-3 text-sm">
          <div>
            <dt className="text-xs text-muted-foreground">Confirmed</dt>
            <dd className="font-heading text-2xl font-semibold">2</dd>
          </div>
          <div>
            <dt className="text-xs text-muted-foreground">Code only</dt>
            <dd className="font-heading text-2xl font-semibold">1</dd>
          </div>
          <div>
            <dt className="text-xs text-muted-foreground">Live only</dt>
            <dd className="font-heading text-2xl font-semibold">2</dd>
          </div>
        </dl>
      </div>

      <ul className="divide-y">
        {findings.map((f) => (
          <li key={f.ids} className="grid grid-cols-[4.5rem_1fr_auto] items-start gap-3 px-4 py-3">
            <SeverityLabel severity={f.severity} className="pt-0.5" />
            <div className="min-w-0">
              <p className="text-sm leading-snug">{f.title}</p>
              <p className="mt-1 font-mono text-[11px] text-muted-foreground">
                {f.ids}
                {f.note ? <span className="font-sans"> · {f.note}</span> : null}
              </p>
            </div>
            <StatusLabel status={f.status} />
          </li>
        ))}
      </ul>

      <figcaption className="sr-only">
        An example SiteShield report with a grade of C and five findings.
      </figcaption>
    </figure>
  );
}
