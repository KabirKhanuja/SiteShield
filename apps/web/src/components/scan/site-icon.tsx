"use client";

import { useState } from "react";
import { GlobeIcon } from "lucide-react";
import { cn } from "@/lib/utils";

/** The scanned site's tab icon, so the report shows which site it is about. */
export function SiteIcon({ src, className }: { src?: string; className?: string }) {
  const [failed, setFailed] = useState(false);

  return (
    <div
      className={cn(
        "flex items-center justify-center rounded-lg border border-outline-variant bg-surface",
        className,
      )}
    >
      {src && !failed ? (
        // Icons come from whatever site was scanned, so next/image's host allowlist does not fit.
        // eslint-disable-next-line @next/next/no-img-element
        <img
          src={src}
          alt=""
          referrerPolicy="no-referrer"
          className="size-1/2 object-contain"
          onError={() => setFailed(true)}
        />
      ) : (
        <GlobeIcon className="size-1/3 text-muted-foreground" aria-hidden />
      )}
    </div>
  );
}
