import Link from "next/link";

/** An inspection tag: the thing an auditor ties to equipment once it has been checked. */
export function LogoMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" aria-hidden className={className}>
      <path d="M7 2h10l4 4v16H3V6z" fill="var(--primary)" />
      <circle cx="12" cy="7" r="1.8" fill="var(--surface)" />
      <path
        d="M8 14.5l2.6 2.6L16.2 11.5"
        fill="none"
        stroke="var(--primary-foreground)"
        strokeWidth="2"
        strokeLinecap="square"
      />
    </svg>
  );
}

export function Logo() {
  return (
    <Link href="/" className="flex items-center gap-2 font-heading text-[17px] font-semibold tracking-tight">
      <LogoMark className="size-6" />
      SiteShield
    </Link>
  );
}
