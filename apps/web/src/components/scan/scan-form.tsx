"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { ArrowRightIcon, LoaderCircleIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { createScan } from "@/lib/api";
import { cn } from "@/lib/utils";

export function ScanForm({ className, autoFocus }: { className?: string; autoFocus?: boolean }) {
  const router = useRouter();
  const [url, setUrl] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setPending(true);
    try {
      const { id } = await createScan(url);
      router.push(`/scan/${id}`);
    } catch (err) {
      setError((err as Error).message);
      setPending(false);
    }
  }

  return (
    <form onSubmit={submit} className={cn("space-y-2", className)} noValidate>
      <label htmlFor="scan-url" className="text-sm font-medium">
        Website to scan
      </label>
      <div className="flex gap-2">
        <input
          id="scan-url"
          name="url"
          type="text"
          inputMode="url"
          autoComplete="url"
          spellCheck={false}
          autoFocus={autoFocus}
          required
          placeholder="yoursite.com"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          aria-invalid={error ? true : undefined}
          aria-describedby={error ? "scan-error" : undefined}
          className="h-10 min-w-0 flex-1 rounded-md border border-input bg-background px-3 font-mono text-sm outline-none placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/30 aria-invalid:border-destructive"
        />
        <Button type="submit" disabled={pending || !url.trim()} className="h-10 px-4">
          {pending ? <LoaderCircleIcon className="animate-spin" /> : null}
          Scan
          {pending ? null : <ArrowRightIcon data-icon="inline-end" />}
        </Button>
      </div>
      {error ? (
        <p id="scan-error" role="alert" className="text-sm text-destructive">
          {error}
        </p>
      ) : null}
    </form>
  );
}
