import Link from "next/link";
import { LogoMark } from "@/components/site/logo";

export function SiteFooter() {
  return (
    <footer className="mt-auto border-t bg-surface-low">
      <div className="mx-auto grid max-w-6xl gap-8 px-4 py-10 text-sm sm:grid-cols-[1fr_auto] sm:px-6">
        <div className="max-w-md space-y-3">
          <div className="flex items-center gap-2 font-heading font-semibold">
            <LogoMark className="size-5" />
            SiteShield
          </div>
          <p className="text-muted-foreground">
            Open source under the MIT license. Built as a course project for Ethical Hacking at VIT.
            The source code rules started from{" "}
            <a className="underline underline-offset-4 hover:text-foreground" href="https://github.com/IAmUnbounded/vibe-guard">
              vibe guard
            </a>
            , also MIT, and grew from there.
          </p>
        </div>
        <nav className="flex gap-6 text-muted-foreground sm:flex-col sm:gap-2">
          <Link className="hover:text-foreground" href="/docs">Documentation</Link>
          <Link className="hover:text-foreground" href="/docs#checks">Check reference</Link>
          <a className="hover:text-foreground" href="https://github.com/KabirKhanuja/SiteShield">GitHub</a>
        </nav>
      </div>
    </footer>
  );
}
