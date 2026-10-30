"use client";

import { CodeBlock } from "@/components/site/code-block";
import { SeverityLabel } from "@/components/site/severity";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { type Finding, type Grade, type Report, type Severity } from "@/lib/api";
import { checks } from "@/lib/checks";
import { cn } from "@/lib/utils";

const GRADE_TEXT: Record<Grade, string> = {
  A: "text-pass",
  B: "text-pass",
  C: "text-sev-medium",
  D: "text-sev-high",
  F: "text-sev-critical",
};

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

const STACK_LABEL: Record<string, string> = {
  nextjs: "Next.js",
  express: "Express",
  nginx: "nginx",
  vercel: "Vercel",
  any: "Any stack",
};

const checkName = (id: string) => checks.find((c) => c.id === id)?.name ?? id;

/** Grade banner, severity counts, findings and the "not checked" list for any report. */
export function ReportResults({ report }: { report: Report }) {
  const findings = [...report.findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  );
  const counts = SEVERITY_ORDER.map((s) => [s, findings.filter((f) => f.severity === s).length] as const);
  const skipped = report.checks.filter((c) => !c.ran);

  return (
    <div className="space-y-12">
      <section className="grid grid-cols-1 gap-4 rounded-xl border bg-surface-low p-5">
        <p className="text-sm text-muted-foreground">
          Grade{" "}
          <span className={cn("font-heading text-2xl font-semibold", GRADE_TEXT[report.grade])}>{report.grade}</span>
          <span className="mx-2">·</span>
          <span className="font-heading text-2xl font-semibold text-foreground">{report.score}</span> out of 100.
          {report.stacks?.length ? (
            <>
              <span className="mx-2">·</span>Detected {report.stacks.map((s) => STACK_LABEL[s] ?? s).join(", ")}.
            </>
          ) : null}
        </p>
        <dl className="flex flex-wrap gap-x-6 gap-y-2">
          {counts.map(([severity, n]) => (
            <div key={severity} className="flex items-center gap-2">
              <dt>
                <SeverityLabel severity={severity} />
              </dt>
              <dd className="font-mono text-sm">{n}</dd>
            </div>
          ))}
        </dl>
      </section>

      <section className="space-y-4">
        <h2 className="font-heading text-2xl font-semibold tracking-tight">
          {findings.length === 0 ? "Nothing found" : findings.length === 1 ? "1 finding" : `${findings.length} findings`}
        </h2>
        {findings.length === 0 ? (
          <p className="text-muted-foreground">Every check passed. Nice work.</p>
        ) : (
          <Accordion type="multiple" className="rounded-lg border">
            {findings.map((f, i) => (
              <FindingItem key={`${f.checkId}-${i}`} finding={f} value={`f${i}`} />
            ))}
          </Accordion>
        )}
      </section>

      {skipped.length > 0 ? (
        <section className="space-y-4">
          <h2 className="font-heading text-2xl font-semibold tracking-tight">Not checked in this scan</h2>
          <ul className="max-w-2xl divide-y rounded-lg border text-sm">
            {skipped.map((c) => (
              <li key={c.checkId} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-3">
                <span className="font-medium">{checkName(c.checkId)}</span>
                <span className="font-mono text-xs text-muted-foreground">{c.checkId}</span>
                <span className="ml-auto text-xs text-muted-foreground">{c.skippedReason}</span>
              </li>
            ))}
          </ul>
        </section>
      ) : null}
    </div>
  );
}

function FindingItem({ finding: f, value }: { finding: Finding; value: string }) {
  const withCode = f.remediation.filter((r) => r.code);
  const withoutCode = f.remediation.filter((r) => !r.code);

  return (
    <AccordionItem value={value} className="px-4">
      <AccordionTrigger className="gap-3 py-3.5 hover:no-underline">
        <span className="grid flex-1 grid-cols-1 gap-1 sm:grid-cols-[5.5rem_1fr_auto] sm:items-center sm:gap-3">
          <SeverityLabel severity={f.severity} />
          <span className="flex items-center gap-2 text-sm font-medium">
            {f.title}
            {f.status === "confirmed" ? (
              <span className="rounded-xs bg-sev-critical/15 px-1.5 py-0.5 text-[0.65rem] font-semibold tracking-wide text-sev-critical uppercase">
                Confirmed
              </span>
            ) : null}
          </span>
          <span className="font-mono text-xs font-normal text-muted-foreground">{f.checkId}</span>
        </span>
      </AccordionTrigger>
      <AccordionContent className="space-y-4 pb-5 sm:pl-[6.25rem]">
        {f.cvss || f.owasp || f.cwe || f.location ? (
          <div className="flex flex-wrap gap-x-3 gap-y-1 text-xs text-muted-foreground">
            {f.cvss ? <span className="rounded-xs bg-surface-mid px-1.5 py-0.5 font-mono">CVSS {f.cvss}</span> : null}
            {f.cwe ? <span className="rounded-xs bg-surface-mid px-1.5 py-0.5 font-mono">{f.cwe}</span> : null}
            {f.owasp ? <span className="rounded-xs bg-surface-mid px-1.5 py-0.5">{f.owasp}</span> : null}
            {f.location ? <span className="font-mono">{f.location}</span> : null}
          </div>
        ) : null}
        <p className="text-pretty text-muted-foreground">{f.detail}</p>
        {f.evidence ? (
          <div className="space-y-1.5">
            <p className="text-xs font-medium">What we saw</p>
            <pre className="overflow-x-auto rounded-md bg-surface-mid px-3 py-2 font-mono text-xs">{f.evidence}</pre>
          </div>
        ) : null}
        {f.remediation.length > 0 ? (
          <div className="space-y-2">
            <p className="text-xs font-medium">How to fix it</p>
            {withoutCode.map((r, i) => (
              <p key={i} className="text-pretty">
                {r.stack !== "any" ? <span className="font-medium">{STACK_LABEL[r.stack]}: </span> : null}
                {r.summary}
              </p>
            ))}
            {withCode.length >= 1 ? (
              <>
                <p className="text-pretty">{withCode[0]!.summary}</p>
                <CodeBlock code={withCode[0]!.code!} file={withCode[0]!.file ?? STACK_LABEL[withCode[0]!.stack]} />
              </>
            ) : null}
          </div>
        ) : null}
      </AccordionContent>
    </AccordionItem>
  );
}
