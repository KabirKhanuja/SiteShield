import type { Metadata } from "next";
import Link from "next/link";
import { CodeScan } from "@/components/scan/code-scan";
import { Command } from "@/components/site/command";
import { SiteFooter } from "@/components/site/site-footer";
import { SiteHeader } from "@/components/site/site-header";
import { sourceChecks } from "@/lib/checks";

export const metadata: Metadata = {
  title: "Scan code",
  description: "Upload a project folder and SiteShield reads the source for security problems, with the exact file and line.",
};

export default function CodeScanPage() {
  return (
    <>
      <SiteHeader />
      <main className="mx-auto grid w-full max-w-6xl flex-1 grid-cols-1 gap-12 px-4 py-10 sm:px-6 lg:grid-cols-[1.1fr_1fr] lg:py-16">
        <div className="space-y-6">
          <h1 className="font-heading text-4xl font-semibold tracking-tight text-balance">Scan your code</h1>
          <p className="max-w-xl text-lg text-pretty text-muted-foreground">
            A live scan only sees the outside of a site. This reads the source behind it. Pick a
            project folder and SiteShield finds the problem before it ships, with the exact file and
            line and a fix you can paste.
          </p>
          <CodeScan />
          <div className="max-w-xl space-y-2">
            <p className="text-sm text-muted-foreground">
              Prefer the terminal? Install from npm and run it against the current project:
            </p>
            <Command value="siteshield scan --src ." />
          </div>
          <p className="max-w-xl text-sm text-muted-foreground">
            Want the live scan instead? <Link href="/scan" className="underline underline-offset-4">Scan a live site</Link>.
          </p>
        </div>

        <div className="space-y-3">
          <h2 className="font-heading text-lg font-semibold">What the code scan looks for</h2>
          <ul className="divide-y rounded-lg border text-sm">
            {sourceChecks.map((c) => (
              <li key={c.id} className="grid grid-cols-[4.25rem_1fr] gap-3 px-4 py-3">
                <span className="font-mono text-xs text-muted-foreground">{c.id}</span>
                <span>{c.name}</span>
              </li>
            ))}
          </ul>
        </div>
      </main>
      <SiteFooter />
    </>
  );
}
