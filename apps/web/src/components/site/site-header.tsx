import Link from "next/link";
import { Logo } from "@/components/site/logo";
import { ThemeToggle } from "@/components/site/theme-toggle";
import { Button } from "@/components/ui/button";

const links = [
  { href: "/scan", label: "Scan" },
  { href: "/#checks", label: "Checks" },
  { href: "/#fixes", label: "Fixes" },
  { href: "/docs", label: "Docs" },
];

export function SiteHeader() {
  return (
    <header className="sticky top-0 z-40 border-b bg-background/90 backdrop-blur">
      <div className="mx-auto flex h-16 max-w-6xl items-center gap-6 px-4 sm:px-6">
        <Logo />
        <nav className="hidden items-center gap-1 sm:flex">
          {links.map((l) => (
            <Button key={l.href} variant="ghost" asChild>
              <Link href={l.href}>{l.label}</Link>
            </Button>
          ))}
        </nav>
        <div className="ml-auto flex items-center gap-1">
          <Button variant="ghost" asChild className="sm:hidden">
            <Link href="/scan">Scan</Link>
          </Button>
          <Button variant="ghost" asChild className="sm:hidden">
            <Link href="/docs">Docs</Link>
          </Button>
          <Button variant="ghost" asChild className="hidden sm:inline-flex">
            <a href="https://github.com/KabirKhanuja/SiteShield">GitHub</a>
          </Button>
          <ThemeToggle />
        </div>
      </div>
    </header>
  );
}
