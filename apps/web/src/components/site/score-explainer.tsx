import { Reveal } from "@/components/site/reveal";
import { cn } from "@/lib/utils";

// Mirrors packages/core/src/scoring.ts. Kept here so the page can show the real numbers.
const COSTS: { sev: string; points: number; color: string }[] = [
  { sev: "Critical", points: 25, color: "text-sev-critical border-sev-critical/40 bg-sev-critical/10" },
  { sev: "High", points: 12, color: "text-sev-high border-sev-high/40 bg-sev-high/10" },
  { sev: "Medium", points: 5, color: "text-sev-medium border-sev-medium/40 bg-sev-medium/10" },
  { sev: "Low", points: 1, color: "text-sev-low border-sev-low/40 bg-sev-low/10" },
  { sev: "Info", points: 0, color: "text-muted-foreground border-border bg-surface-mid" },
];

const BANDS = [
  { grade: "F", range: "0–39", width: 40, color: "bg-sev-critical" },
  { grade: "D", range: "40–59", width: 20, color: "bg-sev-high" },
  { grade: "C", range: "60–74", width: 15, color: "bg-sev-medium" },
  { grade: "B", range: "75–89", width: 15, color: "bg-pass/70" },
  { grade: "A", range: "90–100", width: 10, color: "bg-pass" },
];

export function ScoreExplainer() {
  return (
    <div className="grid gap-8 lg:grid-cols-2">
      <Reveal className="space-y-5 rounded-xl border bg-surface-low p-6">
        <div className="space-y-1">
          <p className="text-sm font-medium text-muted-foreground">Every scan starts at</p>
          <p className="font-heading text-5xl font-semibold">100</p>
        </div>
        <p className="text-sm text-pretty text-muted-foreground">
          Each finding subtracts points based on how serious it is. The points are the same whether the
          problem is in your live site or your code.
        </p>
        <div className="flex flex-wrap gap-2">
          {COSTS.map((c) => (
            <span key={c.sev} className={cn("rounded-md border px-2.5 py-1 font-mono text-sm", c.color)}>
              {c.sev} <span className="font-semibold">−{c.points}</span>
            </span>
          ))}
        </div>
        <div className="rounded-lg border border-dashed p-3 text-sm">
          <span className="font-medium">Confirmed findings cost ×1.5.</span>{" "}
          <span className="text-muted-foreground">
            When the code scan and the live scan point at the same problem, it is real and reachable, so
            it hurts the score more.
          </span>
        </div>
      </Reveal>

      <Reveal delay={120} className="space-y-6 rounded-xl border bg-surface-low p-6">
        <div className="space-y-3">
          <p className="text-sm font-medium text-muted-foreground">The score lands on a grade</p>
          <div className="flex h-10 w-full overflow-hidden rounded-md">
            {BANDS.map((b) => (
              <div
                key={b.grade}
                style={{ width: `${b.width}%` }}
                className={cn("flex items-center justify-center text-sm font-bold text-white", b.color)}
              >
                {b.grade}
              </div>
            ))}
          </div>
          <div className="flex w-full text-[11px] text-muted-foreground">
            {BANDS.map((b) => (
              <div key={b.grade} style={{ width: `${b.width}%` }} className="text-center font-mono">
                {b.range}
              </div>
            ))}
          </div>
        </div>

        <div className="rounded-lg border border-sev-critical/30 bg-sev-critical/5 p-3 text-sm">
          <span className="font-medium text-sev-critical">One hard rule: </span>
          <span className="text-muted-foreground">
            a confirmed critical finding (like a live secret the code also leaks) caps the grade at D, no
            matter how clean everything else is.
          </span>
        </div>

        <div className="space-y-2 rounded-lg bg-surface-mid p-4 font-mono text-sm">
          <p className="text-xs font-sans font-medium text-muted-foreground">Worked example</p>
          <p>100 − (1 critical × 25) − (3 high × 12)</p>
          <p>= 100 − 25 − 36 = <span className="font-semibold">39</span></p>
          <p className="text-sev-critical">→ Grade F</p>
        </div>
      </Reveal>
    </div>
  );
}
