import { cn } from "@/lib/utils";

export type Grade = "A" | "B" | "C" | "D" | "F";

// Neutral tile with only the letter colored, so the grade reads without a tinted fill.
const gradeClass: Record<Grade, string> = {
  A: "text-pass",
  B: "text-pass",
  C: "text-sev-medium",
  D: "text-sev-high",
  F: "text-sev-critical",
};

export function GradeTile({ grade, className }: { grade: Grade; className?: string }) {
  return (
    <div
      className={cn(
        "flex items-center justify-center rounded-lg border border-outline-variant bg-surface font-heading font-bold",
        gradeClass[grade],
        className,
      )}
    >
      {grade}
    </div>
  );
}
