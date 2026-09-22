import type { Metadata } from "next";
import { LockKeyholeIcon } from "lucide-react";
import { ScanForm } from "@/components/scan/scan-form";
import { SiteFooter } from "@/components/site/site-footer";
import { SiteHeader } from "@/components/site/site-header";
import { liveChecks } from "@/lib/checks";

export const metadata: Metadata = {
  title: "Scan a site",
  description: "Run SiteShield's live checks against any public website from your browser.",
};

export default function ScanPage() {
  const running = liveChecks.filter((c) => c.mode === "passive" && ["TLS001", "HDR001", "CKE001", "DNS001"].includes(c.id));
  const later = liveChecks.filter((c) => c.mode === "verified");

  return (
    <>
      <SiteHeader />
      <main className="mx-auto grid w-full max-w-6xl flex-1 grid-cols-1 gap-12 px-4 py-10 sm:px-6 lg:grid-cols-[1.1fr_1fr] lg:py-16">
        <div className="space-y-6">
          <h1 className="font-heading text-4xl font-semibold tracking-tight text-balance">Scan a live site</h1>
          <p className="max-w-xl text-lg text-pretty text-muted-foreground">
            Enter any public website. SiteShield reads what a normal visitor could read, grades it, and
            tells you how to fix each problem it finds.
          </p>
          <ScanForm className="max-w-xl" autoFocus />
          <p className="max-w-xl text-sm text-muted-foreground">
            Local and private addresses are refused. Anyone with a report&apos;s link can open it, so
            share links with care.
          </p>
        </div>

        <div className="space-y-6">
          <div className="space-y-3">
            <h2 className="font-heading text-lg font-semibold">What this scan checks</h2>
            <ul className="divide-y rounded-lg border text-sm">
              {running.map((c) => (
                <li key={c.id} className="grid grid-cols-[4.25rem_1fr] gap-3 px-4 py-3">
                  <span className="font-mono text-xs text-muted-foreground">{c.id}</span>
                  <span>{c.name}</span>
                </li>
              ))}
            </ul>
          </div>
          <div className="space-y-3">
            <h2 className="font-heading text-lg font-semibold">Needs ownership first</h2>
            <ul className="divide-y rounded-lg border text-sm text-muted-foreground">
              {later.map((c) => (
                <li key={c.id} className="grid grid-cols-[4.25rem_1fr_auto] items-center gap-3 px-4 py-3">
                  <span className="font-mono text-xs">{c.id}</span>
                  <span>{c.name}</span>
                  <LockKeyholeIcon className="size-3.5" aria-label="Needs ownership verification" />
                </li>
              ))}
            </ul>
          </div>
        </div>
      </main>
      <SiteFooter />
    </>
  );
}
