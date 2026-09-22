"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { CheckIcon, CircleDashedIcon, LoaderCircleIcon, MinusIcon, RotateCwIcon } from "lucide-react";
import { ScanForm } from "@/components/scan/scan-form";
import { SiteIcon } from "@/components/scan/site-icon";
import { CodeBlock } from "@/components/site/code-block";
import { SeverityLabel } from "@/components/site/severity";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ApiError, createScan, getScan, scanEventsUrl, type Finding, type Grade, type Scan, type Severity } from "@/lib/api";
import { checks } from "@/lib/checks";
import { cn } from "@/lib/utils";

// The checks the website runs today, in the order the engine runs them.
const LIVE_CHECK_IDS = ["TLS001", "HDR001", "CKE001", "DNS001"];
const checkName = (id: string) => checks.find((c) => c.id === id)?.name ?? id;

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

type Progress = Record<string, { state: "running" } | { state: "done"; findings: number; ran: boolean }>;

export function ScanReport({ id }: { id: string }) {
  const [scan, setScan] = useState<Scan | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [progress, setProgress] = useState<Progress>({});

  useEffect(() => {
    let cancelled = false;
    let events: EventSource | null = null;
    let poll: ReturnType<typeof setInterval> | undefined;

    const refresh = async () => {
      const s = await getScan(id);
      if (!cancelled) setScan(s);
      return s;
    };

    // Server sent events can be cut by proxies or sleeping laptops. Polling is the fallback.
    const startPolling = () => {
      poll = setInterval(async () => {
        const s = await refresh().catch(() => null);
        if (s && (s.status === "done" || s.status === "failed")) clearInterval(poll);
      }, 2000);
    };

    const listen = () => {
      events = new EventSource(scanEventsUrl(id));
      const data = (e: Event) => JSON.parse((e as MessageEvent).data);

      events.addEventListener("status", (e) => {
        const { status } = data(e);
        setScan((s) => (s ? { ...s, status } : s));
      });
      events.addEventListener("check:start", (e) => {
        const { checkId } = data(e);
        setProgress((p) => ({ ...p, [checkId]: { state: "running" } }));
      });
      events.addEventListener("check:done", (e) => {
        const { checkId, findings, ran } = data(e);
        setProgress((p) => ({ ...p, [checkId]: { state: "done", findings, ran } }));
      });
      const finish = () => {
        events?.close();
        void refresh().catch(startPolling);
      };
      events.addEventListener("done", finish);
      events.addEventListener("failed", finish);
      events.onerror = () => {
        events?.close();
        startPolling();
      };
    };

    getScan(id)
      .then((s) => {
        if (cancelled) return;
        setScan(s);
        if (s.status === "queued" || s.status === "running") listen();
      })
      .catch((err) => {
        if (!cancelled) setLoadError(err instanceof ApiError ? err.message : "Could not load this scan.");
      });

    return () => {
      cancelled = true;
      events?.close();
      clearInterval(poll);
    };
  }, [id]);

  if (loadError) {
    return (
      <div className="space-y-6">
        <Heading title="Scan not found" />
        <p className="text-muted-foreground">{loadError}</p>
        <ScanForm className="max-w-xl" />
      </div>
    );
  }

  if (!scan) {
    return (
      <p className="flex items-center gap-2 text-muted-foreground">
        <LoaderCircleIcon className="size-4 animate-spin" /> Loading scan
      </p>
    );
  }

  if (scan.status === "queued" || scan.status === "running") {
    return (
      <div className="space-y-8">
        <Heading title="Scanning" target={scan.target} />
        <p className="text-muted-foreground">
          {scan.status === "queued" ? "Waiting for a free slot." : "Running the live checks. This usually takes 10 to 30 seconds."}
        </p>
        <ol className="max-w-xl divide-y rounded-lg border">
          {LIVE_CHECK_IDS.map((checkId) => {
            const p = progress[checkId];
            return (
              <li key={checkId} className="flex items-center gap-3 px-4 py-3 text-sm">
                {!p ? (
                  <CircleDashedIcon className="size-4 text-muted-foreground" aria-label="Waiting" />
                ) : p.state === "running" ? (
                  <LoaderCircleIcon className="size-4 animate-spin text-primary-text" aria-label="Running" />
                ) : p.ran ? (
                  <CheckIcon className="size-4 text-pass" aria-label="Done" />
                ) : (
                  <MinusIcon className="size-4 text-muted-foreground" aria-label="Did not run" />
                )}
                <span className="font-medium">{checkName(checkId)}</span>
                <span className="font-mono text-xs text-muted-foreground">{checkId}</span>
                <span className="ml-auto text-xs text-muted-foreground">
                  {p?.state === "done" ? (p.ran ? `${p.findings} found` : "could not run") : null}
                </span>
              </li>
            );
          })}
        </ol>
      </div>
    );
  }

  if (scan.status === "failed" || !scan.report) {
    return (
      <div className="space-y-6">
        <Heading title="The scan did not finish" target={scan.target} />
        <p className="max-w-xl rounded-lg border border-destructive/40 bg-destructive/5 p-4 text-sm">
          {scan.error ?? "Something went wrong while scanning."}
        </p>
        <ScanForm className="max-w-xl" />
      </div>
    );
  }

  return <Results scan={scan} report={scan.report} />;
}

function Heading({ title, target }: { title: string; target?: string }) {
  return (
    <div className="space-y-2">
      <h1 className="font-heading text-3xl font-semibold tracking-tight sm:text-4xl">{title}</h1>
      {target ? <p className="font-mono text-sm text-muted-foreground">{target}</p> : null}
    </div>
  );
}

function Results({ scan, report }: { scan: Scan; report: NonNullable<Scan["report"]> }) {
  const router = useRouter();
  const [rescanning, setRescanning] = useState(false);
  const [rescanError, setRescanError] = useState<string | null>(null);

  const findings = [...report.findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  );
  const counts = SEVERITY_ORDER.map((s) => [s, findings.filter((f) => f.severity === s).length] as const);
  const skipped = report.checks.filter((c) => !c.ran);

  async function rescan() {
    setRescanning(true);
    setRescanError(null);
    try {
      const { id } = await createScan(scan.target);
      router.push(`/scan/${id}`);
    } catch (err) {
      setRescanError((err as Error).message);
      setRescanning(false);
    }
  }

  return (
    <div className="space-y-12">
      <div className="flex flex-col gap-6 sm:flex-row sm:items-end sm:justify-between">
        <Heading title="Scan report" target={report.target} />
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" onClick={rescan} disabled={rescanning}>
            <RotateCwIcon data-icon="inline-start" className={rescanning ? "animate-spin" : undefined} />
            Scan again
          </Button>
          <Button variant="ghost" asChild>
            <Link href="/scan">Scan another site</Link>
          </Button>
        </div>
      </div>
      {rescanError ? <p className="text-sm text-destructive">{rescanError}</p> : null}

      <section className="grid grid-cols-1 gap-6 rounded-xl border bg-surface-low p-5 sm:grid-cols-[auto_1fr] sm:items-center">
        <SiteIcon src={report.icon} className="size-24" />
        <div className="space-y-4">
          <p className="text-sm text-muted-foreground">
            Grade{" "}
            <span className={cn("font-heading text-2xl font-semibold", GRADE_TEXT[report.grade])}>{report.grade}</span>
            <span className="mx-2">·</span>
            <span className="font-heading text-2xl font-semibold text-foreground">{report.score}</span> out of 100.
            Scanned {new Date(report.finishedAt).toLocaleString()}.
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
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="font-heading text-2xl font-semibold tracking-tight">
          {findings.length === 0 ? "Nothing found" : findings.length === 1 ? "1 finding" : `${findings.length} findings`}
        </h2>
        {findings.length === 0 ? (
          <p className="text-muted-foreground">Every live check passed. Nice work.</p>
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
          <p className="max-w-2xl text-sm text-pretty text-muted-foreground">
            The website runs the passive live checks, the ones that only read what any visitor can see.
            Checks that send test traffic wait for ownership verification, and the source code checks
            run from the CLI against your repository.
          </p>
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
          <span className="text-sm font-medium">{f.title}</span>
          <span className="font-mono text-xs font-normal text-muted-foreground">{f.checkId}</span>
        </span>
      </AccordionTrigger>
      <AccordionContent className="space-y-4 pb-5 sm:pl-[6.25rem]">
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
            {withCode.length === 1 ? (
              <>
                <p className="text-pretty">{withCode[0]!.summary}</p>
                <CodeBlock code={withCode[0]!.code!} file={withCode[0]!.file ?? STACK_LABEL[withCode[0]!.stack]} />
              </>
            ) : withCode.length > 1 ? (
              <Tabs defaultValue={withCode[0]!.stack} className="min-w-0">
                <TabsList className="max-w-full overflow-x-auto">
                  {withCode.map((r) => (
                    <TabsTrigger key={r.stack} value={r.stack} className="px-3">
                      {STACK_LABEL[r.stack]}
                    </TabsTrigger>
                  ))}
                </TabsList>
                {withCode.map((r) => (
                  <TabsContent key={r.stack} value={r.stack} className="space-y-2">
                    <p className="text-pretty">{r.summary}</p>
                    <CodeBlock code={r.code!} file={r.file ?? STACK_LABEL[r.stack]} />
                  </TabsContent>
                ))}
              </Tabs>
            ) : null}
          </div>
        ) : null}
      </AccordionContent>
    </AccordionItem>
  );
}
