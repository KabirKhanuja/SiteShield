import { GlobeIcon, LockKeyholeIcon, FileCode2Icon } from "lucide-react";
import { Reveal } from "@/components/site/reveal";
import { liveChecks, sourceChecks, type Check } from "@/lib/checks";
import { cn } from "@/lib/utils";

function Tile({ check, accent, delay }: { check: Check; accent: string; delay: number }) {
  return (
    <Reveal
      delay={delay}
      className={cn(
        "group rounded-lg border border-l-2 bg-surface-low p-3 transition hover:-translate-y-0.5 hover:shadow-sm",
        accent,
      )}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="font-mono text-xs text-muted-foreground">{check.id}</span>
        {check.mode === "verified" ? (
          <LockKeyholeIcon className="size-3 text-muted-foreground" aria-label="Needs ownership verification" />
        ) : null}
      </div>
      <p className="mt-1 text-sm font-medium leading-snug">{check.name}</p>
    </Reveal>
  );
}

function Panel({
  icon,
  title,
  blurb,
  count,
  checks,
  accent,
}: {
  icon: React.ReactNode;
  title: string;
  blurb: string;
  count: number;
  checks: Check[];
  accent: string;
}) {
  return (
    <div className="space-y-4">
      <div className="flex items-start gap-3">
        <span className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-surface-mid text-primary-text">
          {icon}
        </span>
        <div>
          <h3 className="font-heading text-lg font-semibold">
            {title} <span className="text-muted-foreground">· {count}</span>
          </h3>
          <p className="text-sm text-muted-foreground">{blurb}</p>
        </div>
      </div>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-2 xl:grid-cols-3">
        {checks.map((c, i) => (
          <Tile key={c.id} check={c} accent={accent} delay={i * 45} />
        ))}
      </div>
    </div>
  );
}

export function ChecksShowcase() {
  return (
    <div className="grid gap-10 lg:grid-cols-2 lg:gap-12">
      <Panel
        icon={<GlobeIcon className="size-5" />}
        title="Live scan"
        blurb="Reads your running site the way a visitor can. Three checks that send test traffic wait until you verify you own the domain."
        count={liveChecks.length}
        checks={liveChecks}
        accent="border-l-primary-text/40"
      />
      <Panel
        icon={<FileCode2Icon className="size-5" />}
        title="Code scan"
        blurb="Reads your source and flags the problem before it ships, with the exact file and line."
        count={sourceChecks.length}
        checks={sourceChecks}
        accent="border-l-sev-high/40"
      />
    </div>
  );
}
