"use client";

import { useEffect, useRef, useState } from "react";
import { cn } from "@/lib/utils";

type Line =
  | { kind: "cmd"; text: string }
  | { kind: "out"; text: string; tone?: "ok" | "muted" }
  | { kind: "finding"; id: string; sev: "critical" | "high" | "medium"; title: string }
  | { kind: "grade"; grade: string; score: number };

const SCRIPT: Line[] = [
  { kind: "cmd", text: "npm install -g @kabirkhanuja/siteshield" },
  { kind: "out", text: "+ @kabirkhanuja/siteshield@0.1.1", tone: "ok" },
  { kind: "cmd", text: "siteshield scan --src ." },
  { kind: "out", text: "reading project, 42 files…", tone: "muted" },
  { kind: "finding", id: "DEP001", sev: "critical", title: "lodash@4.17.11 has 7 known advisories" },
  { kind: "finding", id: "SEC001", sev: "high", title: "Secret committed in .env" },
  { kind: "finding", id: "COR002", sev: "high", title: "CORS allows every origin with credentials" },
  { kind: "finding", id: "INJ002", sev: "high", title: "SQL built by string concatenation" },
  { kind: "finding", id: "XSS001", sev: "high", title: "innerHTML with unsanitised value" },
  { kind: "grade", grade: "F", score: 0 },
];

const SEV_COLOR: Record<string, string> = {
  critical: "text-sev-critical",
  high: "text-sev-high",
  medium: "text-sev-medium",
};

function prefersReducedMotion() {
  return typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
}

export function AnimatedTerminal({ className }: { className?: string }) {
  // step = how many script lines are fully shown; typed = chars typed for a current command line.
  const [step, setStep] = useState(0);
  const [typed, setTyped] = useState(0);
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined);

  useEffect(() => {
    if (prefersReducedMotion()) {
      setStep(SCRIPT.length);
      return;
    }
    const current = SCRIPT[step];
    if (!current) {
      // Finished: hold the result, then restart the loop.
      timer.current = setTimeout(() => {
        setStep(0);
        setTyped(0);
      }, 3200);
      return () => clearTimeout(timer.current);
    }
    if (current.kind === "cmd" && typed < current.text.length) {
      timer.current = setTimeout(() => setTyped((t) => t + 1), 38);
      return () => clearTimeout(timer.current);
    }
    const pause = current.kind === "cmd" ? 420 : current.kind === "finding" ? 360 : current.kind === "grade" ? 200 : 300;
    timer.current = setTimeout(() => {
      setStep((s) => s + 1);
      setTyped(0);
    }, pause);
    return () => clearTimeout(timer.current);
  }, [step, typed]);

  return (
    <div className={cn("overflow-hidden rounded-xl border bg-[#0d1117] text-[13px] shadow-lg shadow-black/20", className)}>
      <div className="flex items-center gap-2 border-b border-white/10 px-4 py-2.5">
        <span className="size-3 rounded-full bg-[#ff5f57]" />
        <span className="size-3 rounded-full bg-[#febc2e]" />
        <span className="size-3 rounded-full bg-[#28c840]" />
        <span className="ml-2 font-mono text-xs text-white/40">siteshield — zsh</span>
      </div>
      <div className="min-h-[340px] space-y-1 p-4 font-mono leading-relaxed">
        {SCRIPT.map((line, i) => {
          if (i > step) return null;
          const typing = i === step && line.kind === "cmd";
          return <TerminalLine key={i} line={line} typedChars={typing ? typed : undefined} active={i === step} />;
        })}
      </div>
    </div>
  );
}

function TerminalLine({ line, typedChars, active }: { line: Line; typedChars?: number; active: boolean }) {
  if (line.kind === "cmd") {
    const shown = typedChars === undefined ? line.text : line.text.slice(0, typedChars);
    return (
      <div className="ss-rise flex gap-2 text-white">
        <span className="text-sev-high">$</span>
        <span>
          {shown}
          {typedChars !== undefined && <span className="ss-caret ml-0.5 h-[1.05em] align-middle" />}
        </span>
      </div>
    );
  }
  if (line.kind === "out") {
    return <div className={cn("ss-rise pl-4", line.tone === "ok" ? "text-pass" : "text-white/45")}>{line.text}</div>;
  }
  if (line.kind === "grade") {
    return (
      <div className="ss-rise mt-2 flex items-center gap-3 border-t border-white/10 pt-3">
        <span className="flex size-9 items-center justify-center rounded-md bg-sev-critical/20 font-bold text-sev-critical">
          {line.grade}
        </span>
        <span className="text-white/70">
          Grade {line.grade} · {line.score}/100 · 5 findings
        </span>
      </div>
    );
  }
  return (
    <div className={cn("ss-rise flex items-center gap-2 pl-4", active && "")}>
      <span className={cn("w-[4.6rem] shrink-0 text-[11px] font-semibold uppercase tracking-wide", SEV_COLOR[line.sev])}>
        {line.sev}
      </span>
      <span className="text-white/35">{line.id}</span>
      <span className="truncate text-white/80">{line.title}</span>
    </div>
  );
}
