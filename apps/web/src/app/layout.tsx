import type { Metadata } from "next";
import { IBM_Plex_Mono, IBM_Plex_Sans, Schibsted_Grotesk } from "next/font/google";
import { BackToTop } from "@/components/site/back-to-top";
import { TooltipProvider } from "@/components/ui/tooltip";
import "./globals.css";

// Schibsted Grotesk was drawn for a newsroom: tight, confident headlines and clear figures,
// which matters for a page built around a letter grade. Plex Sans and Plex Mono share
// proportions, so prose and terminal output sit comfortably next to each other.
const display = Schibsted_Grotesk({
  variable: "--font-display",
  subsets: ["latin"],
  weight: ["500", "600", "700"],
});

const body = IBM_Plex_Sans({
  variable: "--font-body",
  subsets: ["latin"],
  weight: ["400", "500", "600"],
});

const code = IBM_Plex_Mono({
  variable: "--font-code",
  subsets: ["latin"],
  weight: ["400", "500"],
});

export const metadata: Metadata = {
  title: {
    default: "SiteShield",
    template: "%s · SiteShield",
  },
  description:
    "Audit your live website and your source code together, get one security grade, and fix each issue with code written for your stack.",
};

// Runs before first paint so a saved or system dark preference never flashes light.
const themeScript = `(function(){try{var t=localStorage.getItem("theme");var d=t?t==="dark":matchMedia("(prefers-color-scheme: dark)").matches;if(d)document.documentElement.classList.add("dark")}catch(e){}})()`;

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html
      lang="en"
      suppressHydrationWarning
      className={`${display.variable} ${body.variable} ${code.variable} h-full antialiased`}
    >
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeScript }} />
      </head>
      <body className="flex min-h-full flex-col">
        <TooltipProvider>
          {children}
          <BackToTop />
        </TooltipProvider>
      </body>
    </html>
  );
}
