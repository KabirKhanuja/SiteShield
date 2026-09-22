import { CopyButton } from "@/components/site/copy-button";
import { cn } from "@/lib/utils";

export function CodeBlock({
  code,
  file,
  className,
}: {
  code: string;
  file?: string;
  className?: string;
}) {
  return (
    <div className={cn("overflow-hidden rounded-lg border bg-surface-low", className)}>
      <div className="flex h-10 items-center justify-between border-b px-3">
        <span className="font-mono text-xs text-muted-foreground">{file}</span>
        <CopyButton value={code} />
      </div>
      <pre className="overflow-x-auto p-4 font-mono text-[13px] leading-relaxed">
        <code>{code}</code>
      </pre>
    </div>
  );
}
