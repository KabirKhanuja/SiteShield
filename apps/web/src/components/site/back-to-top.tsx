"use client";

import { useEffect, useState } from "react";
import { ArrowUpIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

/** Appears once the reader is a screen or so down the page. */
export function BackToTop() {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const update = () => setVisible(window.scrollY > 600);
    update();
    window.addEventListener("scroll", update, { passive: true });
    return () => window.removeEventListener("scroll", update);
  }, []);

  function toTop() {
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    window.scrollTo({ top: 0, behavior: reduce ? "auto" : "smooth" });
  }

  return (
    <Button
      size="icon-lg"
      onClick={toTop}
      aria-label="Back to top"
      tabIndex={visible ? 0 : -1}
      aria-hidden={!visible}
      className={cn(
        "fixed right-4 bottom-4 z-40 size-11 shadow-md transition-[opacity,translate] duration-200 sm:right-6 sm:bottom-6",
        "motion-reduce:transition-none",
        visible ? "translate-y-0 opacity-100" : "pointer-events-none translate-y-2 opacity-0",
      )}
    >
      <ArrowUpIcon className="size-5" />
    </Button>
  );
}
