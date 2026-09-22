import { CopyButton } from "@/components/site/copy-button";
import { cn } from "@/lib/utils";

/** A single shell command on one line, the thing we most want people to copy. */
export function Command({ value, className }: { value: string; className?: string }) {
  return (
    <div
      className={cn(
        "flex items-center gap-3 rounded-md border bg-surface-low py-1.5 pr-1.5 pl-4 font-mono text-sm",
        className,
      )}
    >
      <span aria-hidden className="select-none text-primary-text">
        $
      </span>
      <code className="min-w-0 flex-1 overflow-x-auto whitespace-nowrap">{value}</code>
      <CopyButton value={value} />
    </div>
  );
}
