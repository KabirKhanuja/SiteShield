import type { Metadata } from "next";
import Link from "next/link";
import { ArrowRightIcon } from "lucide-react";
import { CiPipeline } from "@/components/site/ci-pipeline";
import { CodeBlock } from "@/components/site/code-block";
import { Command } from "@/components/site/command";
import { Reveal } from "@/components/site/reveal";
import { SiteFooter } from "@/components/site/site-footer";
import { SiteHeader } from "@/components/site/site-header";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { usage } from "@/lib/examples";

export const metadata: Metadata = {
  title: "Install and run locally",
  description: "Install @kabirkhanuja/siteshield from npm and run the scanner in your terminal, in CI, or as a library.",
};

const steps = [
  {
    title: "Ask for a token",
    body: "Run siteshield verify with your domain. You get a random token tied to this site and this machine.",
  },
  {
    title: "Publish it",
    body: "Add it as a DNS TXT record, or serve it from /.well-known/siteshield.txt. Either one proves you control the site.",
  },
  {
    title: "Scan with active checks",
    body: "Rate limiting, exposed file and injection checks unlock. Every request they send is written to an audit log you keep.",
  },
];

export default function InstallPage() {
  return (
    <>
      <SiteHeader />
      <main className="mx-auto w-full max-w-5xl flex-1 px-4 py-12 sm:px-6 lg:py-16">
        <Reveal className="max-w-2xl space-y-4">
          <span className="inline-flex items-center gap-2 rounded-full border bg-surface-low px-3 py-1 text-xs font-medium text-muted-foreground">
            <span className="size-1.5 rounded-full bg-pass" /> @kabirkhanuja/siteshield on npm
          </span>
          <h1 className="font-heading text-4xl font-semibold tracking-tight text-balance">Run it in your own terminal</h1>
          <p className="text-lg text-pretty text-muted-foreground">
            The browser scans are the quick way in. For your own projects, in CI, or inside your tooling,
            install the package and run the same engine locally.
          </p>
        </Reveal>

        <section className="mt-12 space-y-4">
          <h2 className="font-heading text-xl font-semibold">Install</h2>
          <Reveal className="space-y-4">
            <p className="text-sm text-muted-foreground">Install once, then the command is just <code className="rounded bg-surface-mid px-1 py-0.5 font-mono text-xs">siteshield</code>:</p>
            <Command value="npm install -g @kabirkhanuja/siteshield" />
            <p className="text-sm text-muted-foreground">Or run it without installing anything, straight through npx:</p>
            <Command value="npx @kabirkhanuja/siteshield scan --src ." />
            <p className="text-sm text-muted-foreground">
              Requires Node 20 or newer. The package name carries the <code className="rounded bg-surface-mid px-1 py-0.5 font-mono text-xs">@kabirkhanuja/</code> prefix, but the command you type is always <code className="rounded bg-surface-mid px-1 py-0.5 font-mono text-xs">siteshield</code>.
            </p>
          </Reveal>
        </section>

        <section className="mt-14 space-y-4">
          <h2 className="font-heading text-xl font-semibold">Use it</h2>
          <Reveal>
            <Tabs defaultValue={usage[0].label} className="min-w-0">
              <TabsList className="max-w-full overflow-x-auto">
                {usage.map((s) => (
                  <TabsTrigger key={s.label} value={s.label} className="px-3">
                    {s.label}
                  </TabsTrigger>
                ))}
              </TabsList>
              {usage.map((s) => (
                <TabsContent key={s.label} value={s.label}>
                  <CodeBlock code={s.code} file={s.file} />
                </TabsContent>
              ))}
            </Tabs>
          </Reveal>
        </section>

        <section className="mt-14 space-y-6">
          <div className="max-w-2xl space-y-2">
            <h2 className="font-heading text-xl font-semibold">Gate your pull requests</h2>
            <p className="text-pretty text-muted-foreground">
              The GitHub Action scans every pull request and fails the build on anything high or critical,
              so a bad change never reaches main.
            </p>
          </div>
          <Reveal>
            <CiPipeline className="max-w-xl" />
          </Reveal>
        </section>

        <section className="mt-14 space-y-6">
          <div className="max-w-2xl space-y-2">
            <h2 className="font-heading text-xl font-semibold">Active checks need proof of ownership</h2>
            <p className="text-pretty text-muted-foreground">
              Sending login attempts or test payloads to a server you do not own is an offence in most
              countries, including under the IT Act in India. So SiteShield asks for proof first, the same
              way search consoles and certificate authorities do.
            </p>
          </div>
          <ol className="grid gap-4 sm:grid-cols-3">
            {steps.map((s, i) => (
              <Reveal as="li" key={s.title} delay={i * 110} className="space-y-2 rounded-xl border bg-surface-low p-5">
                <span className="flex size-8 items-center justify-center rounded-sm bg-primary-container font-heading text-sm font-semibold text-on-primary-container">
                  {i + 1}
                </span>
                <p className="font-medium">{s.title}</p>
                <p className="text-sm text-pretty text-muted-foreground">{s.body}</p>
              </Reveal>
            ))}
          </ol>
        </section>

        <div className="mt-14 flex flex-wrap gap-2">
          <Button asChild variant="outline">
            <Link href="/docs">
              Full documentation
              <ArrowRightIcon data-icon="inline-end" />
            </Link>
          </Button>
          <Button asChild variant="ghost">
            <a href="https://www.npmjs.com/package/@kabirkhanuja/siteshield">View on npm</a>
          </Button>
        </div>
      </main>
      <SiteFooter />
    </>
  );
}
