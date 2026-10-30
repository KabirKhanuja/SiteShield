import { CheckIcon, GitPullRequestIcon, XIcon } from "lucide-react";
import { Reveal } from "@/components/site/reveal";
import { cn } from "@/lib/utils";

const STEPS = [
  { label: "Checkout code", sub: "actions/checkout@v4", ok: true },
  { label: "Set up Node 22", sub: "actions/setup-node@v4", ok: true },
  { label: "Scan source", sub: "siteshield scan --src . --format sarif", ok: true },
  { label: "Upload results", sub: "findings posted to the Security tab", ok: true },
  { label: "Fail on high or critical", sub: "2 high findings — exit code 2", ok: false },
];

export function CiPipeline({ className }: { className?: string }) {
  return (
    <div className={cn("overflow-hidden rounded-xl border bg-surface-low", className)}>
      <div className="flex items-center gap-2 border-b bg-surface-mid px-4 py-3 text-sm">
        <GitPullRequestIcon className="size-4 text-primary-text" />
        <span className="font-medium">security</span>
        <span className="font-mono text-xs text-muted-foreground">pull request #42</span>
      </div>
      <ol className="divide-y">
        {STEPS.map((s, i) => (
          <Reveal as="li" key={s.label} delay={i * 110} className="flex items-center gap-3 px-4 py-3">
            <span
              className={cn(
                "flex size-6 shrink-0 items-center justify-center rounded-full",
                s.ok ? "bg-pass/15 text-pass" : "bg-sev-critical/15 text-sev-critical",
              )}
            >
              {s.ok ? <CheckIcon className="size-3.5" /> : <XIcon className="size-3.5" />}
            </span>
            <span className="min-w-0">
              <span className="block text-sm font-medium">{s.label}</span>
              <span className="block truncate font-mono text-xs text-muted-foreground">{s.sub}</span>
            </span>
          </Reveal>
        ))}
      </ol>
      <Reveal delay={STEPS.length * 110} className="flex items-center gap-2 border-t border-sev-critical/30 bg-sev-critical/10 px-4 py-3 text-sm">
        <XIcon className="size-4 text-sev-critical" />
        <span className="font-medium text-sev-critical">Merge blocked</span>
        <span className="text-muted-foreground">— one check failed, so the pull request cannot be merged.</span>
      </Reveal>
    </div>
  );
}
