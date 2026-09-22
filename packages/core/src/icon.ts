/**
 * Finds the icon a browser would show in the tab for this page, so reports can show which
 * site they are about. Prefers apple-touch-icon because it is usually 180px and stays sharp
 * at report size, then an SVG icon, then any icon, then the /favicon.ico every browser tries.
 */
export function findIcon(html: string, pageUrl: URL): string {
  const candidates: { href: string; rank: number }[] = [];

  for (const tag of html.match(/<link\b[^>]*>/gi) ?? []) {
    const rel = attr(tag, "rel")?.toLowerCase().split(/\s+/) ?? [];
    const href = attr(tag, "href");
    if (!href) continue;

    let rank: number;
    if (rel.includes("apple-touch-icon") || rel.includes("apple-touch-icon-precomposed")) rank = 0;
    else if (rel.includes("icon") && (attr(tag, "type") === "image/svg+xml" || /\.svg(\?|$)/i.test(href))) rank = 1;
    else if (rel.includes("icon")) rank = 2;
    else continue;

    candidates.push({ href, rank });
  }

  candidates.sort((a, b) => a.rank - b.rank);
  for (const { href } of candidates) {
    try {
      const url = new URL(decodeEntities(href), pageUrl);
      // Only links a browser can load; javascript: or data: hrefs are ignored.
      if (url.protocol === "https:" || url.protocol === "http:") return url.href;
    } catch {
      // A malformed href, try the next one.
    }
  }
  return new URL("/favicon.ico", pageUrl).href;
}

function attr(tag: string, name: string): string | undefined {
  const m = tag.match(new RegExp(`\\s${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, "i"));
  return m ? (m[1] ?? m[2] ?? m[3])?.trim() : undefined;
}

function decodeEntities(s: string): string {
  return s.replace(/&amp;/g, "&").replace(/&#x2F;/gi, "/").replace(/&#47;/g, "/");
}
