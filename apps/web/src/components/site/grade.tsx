import { cn } from "@/lib/utils";

export type Grade = "A" | "B" | "C" | "D" | "F";

// Tinted container with the letter in the full color, the way Material 3 pairs a
// container with its "on" color. Readable in both themes without a white or black fill.
const gradeClass: Record<Grade, string> = {
  A: "bg-pass/15 text-pass",
  B: "bg-pass/10 text-pass",
  C: "bg-sev-medium/20 text-sev-medium",
  D: "bg-sev-high/15 text-sev-high",
  F: "bg-sev-critical/15 text-sev-critical",
};

export function GradeTile({ grade, className }: { grade: Grade; className?: string }) {
  return (
    <div
      className={cn(
        "flex items-center justify-center rounded-lg font-heading font-bold",
        gradeClass[grade],
        className,
      )}
    >
      {grade}
    </div>
  );
}
