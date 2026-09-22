"use client";

import { useState } from "react";
import { MenuIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetTitle, SheetTrigger } from "@/components/ui/sheet";

export type DocLink = { id: string; label: string };

function NavList({ links, onNavigate }: { links: DocLink[]; onNavigate?: () => void }) {
  return (
    <ul className="space-y-0.5 text-sm">
      {links.map((l) => (
        <li key={l.id}>
          <a
            href={`#${l.id}`}
            onClick={onNavigate}
            className="block rounded-sm px-3 py-1.5 text-muted-foreground hover:bg-surface-mid hover:text-foreground"
          >
            {l.label}
          </a>
        </li>
      ))}
    </ul>
  );
}

export function DocsSidebar({ links }: { links: DocLink[] }) {
  return (
    <nav aria-label="Documentation" className="sticky top-24 hidden max-h-[calc(100vh-7rem)] overflow-y-auto lg:block">
      <NavList links={links} />
    </nav>
  );
}

export function DocsMobileNav({ links }: { links: DocLink[] }) {
  const [open, setOpen] = useState(false);
  return (
    <Sheet open={open} onOpenChange={setOpen}>
      <SheetTrigger asChild>
        <Button variant="outline" className="lg:hidden">
          <MenuIcon data-icon="inline-start" />
          On this page
        </Button>
      </SheetTrigger>
      <SheetContent side="left" className="p-4 pt-12">
        <SheetTitle className="sr-only">On this page</SheetTitle>
        <NavList links={links} onNavigate={() => setOpen(false)} />
      </SheetContent>
    </Sheet>
  );
}
