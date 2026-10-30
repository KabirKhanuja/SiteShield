import Link from "next/link";
import { ArrowRightIcon, FileCode2Icon, GlobeIcon, TerminalIcon } from "lucide-react";
import { AnimatedTerminal } from "@/components/site/animated-terminal";
import { ChecksShowcase } from "@/components/site/checks-showcase";
import { CiPipeline } from "@/components/site/ci-pipeline";
import { CodeBlock } from "@/components/site/code-block";
import { Reveal } from "@/components/site/reveal";
import { ScoreExplainer } from "@/components/site/score-explainer";
import { SeverityLabel, StatusLabel } from "@/components/site/severity";
import { SiteFooter } from "@/components/site/site-footer";
import { SiteHeader } from "@/components/site/site-header";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { headerFixes } from "@/lib/examples";

export default function Home() {
  return (
    <>
      <SiteHeader />
      <main className="flex-1">
        <Hero />
        <Confirmation />
        <Checks />
        <Fixes />
        <Ci />
        <Grades />
        <RunItYourWay />
      </main>
      <SiteFooter />
    </>
  );
}

function Container({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return <div className={`mx-auto max-w-6xl px-4 sm:px-6 ${className}`}>{children}</div>;
}

function SectionHeading({ title, children }: { title: string; children?: React.ReactNode }) {
  return (
    <Reveal className="max-w-2xl space-y-3">
      <h2 className="font-heading text-3xl font-semibold tracking-tight text-balance sm:text-[34px]">{title}</h2>
      {children ? <div className="text-pretty text-muted-foreground">{children}</div> : null}
    </Reveal>
  );
}

function Hero() {
  return (
    <section className="border-b">
      <Container className="grid grid-cols-1 gap-12 py-14 lg:grid-cols-[1fr_1.05fr] lg:items-center lg:py-20">
        <div className="space-y-7">
          <span className="inline-flex items-center gap-2 rounded-full border bg-surface-low px-3 py-1 text-xs font-medium text-muted-foreground">
            <span className="size-1.5 rounded-full bg-pass" /> Published on npm · @kabirkhanuja/siteshield
          </span>
          <h1 className="font-heading text-4xl leading-[1.08] font-semibold tracking-tight text-balance sm:text-5xl lg:text-[56px]">
            Audit the site you shipped and the code behind it, in one pass.
          </h1>
          <p className="max-w-xl text-lg text-pretty text-muted-foreground">
            SiteShield scans your live website and your source code together, then gives one A to F grade
            with the fix for every problem. When both layers point at the same thing, it is marked
            confirmed.
          </p>
          <div className="flex flex-wrap gap-2">
            <Button asChild size="lg" className="px-4">
              <Link href="/scan">
                <GlobeIcon data-icon="inline-start" />
                Scan a site
              </Link>
            </Button>
            <Button asChild size="lg" variant="outline" className="px-4">
              <Link href="/scan/code">
                <FileCode2Icon data-icon="inline-start" />
                Scan your code
              </Link>
            </Button>
            <Button asChild size="lg" variant="ghost" className="px-4">
              <Link href="/install">
                <TerminalIcon data-icon="inline-start" />
                Run it locally
              </Link>
            </Button>
          </div>
        </div>
        <AnimatedTerminal className="ss-float lg:justify-self-end" />
      </Container>
    </section>
  );
}

function Confirmation() {
  return (
    <section className="border-b bg-surface-low py-16 lg:py-24">
      <Container className="space-y-10">
        <SectionHeading title="When the code and the site agree, it is not a guess">
          Scanners that read only code flag things that never reach production. Scanners that probe only
          the site cannot tell you which line to change. SiteShield runs both and matches the results.
        </SectionHeading>

        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <Reveal className="overflow-hidden rounded-lg border bg-background">
            <div className="flex h-10 items-center justify-between border-b px-4 text-xs">
              <span className="font-medium">What the code says</span>
              <span className="font-mono text-muted-foreground">src/server.ts:12</span>
            </div>
            <pre className="overflow-x-auto p-4 font-mono text-[13px] leading-relaxed">
              <code>
                {"app.use(\n  cors({\n"}
                <mark className="bg-primary-container text-on-primary-container">
                  {"    origin: (origin, cb) => cb(null, origin),"}
                </mark>
                {"\n    credentials: true,\n  })\n);"}
              </code>
            </pre>
          </Reveal>
          <Reveal delay={140} className="overflow-hidden rounded-lg border bg-background">
            <div className="flex h-10 items-center justify-between border-b px-4 text-xs">
              <span className="font-medium">What the site does</span>
              <span className="font-mono text-muted-foreground">GET /api/me</span>
            </div>
            <pre className="overflow-x-auto p-4 font-mono text-[13px] leading-relaxed">
              <code>
                {"> Origin: https://attacker.test\n\n< HTTP/2 200\n"}
                <mark className="bg-primary-container text-on-primary-container">
                  {"< access-control-allow-origin: https://attacker.test"}
                </mark>
                {"\n< access-control-allow-credentials: true"}
              </code>
            </pre>
          </Reveal>
        </div>

        <Reveal className="flex flex-col gap-2 sm:flex-row sm:gap-6">
          <div className="flex shrink-0 items-start gap-4">
            <StatusLabel status="confirmed" />
            <SeverityLabel severity="high" className="pt-0.5" />
          </div>
          <p className="text-sm text-pretty text-muted-foreground">
            The config reflects any origin and the live API proves it. A page on any other domain can
            read <span className="font-mono text-foreground">/api/me</span> as your logged in user. The
            fix goes on line 12.
          </p>
        </Reveal>
      </Container>
    </section>
  );
}

function Checks() {
  return (
    <section id="checks" className="py-16 lg:py-24">
      <Container className="space-y-12">
        <SectionHeading title="Twenty checks across two layers">
          Checks that only read public information run on any site. The ones that send test traffic wait
          until you prove the site is yours.
        </SectionHeading>
        <ChecksShowcase />
      </Container>
    </section>
  );
}

function Fixes() {
  return (
    <section id="fixes" className="border-y bg-surface-low py-16 lg:py-24">
      <Container className="grid grid-cols-1 gap-10 lg:grid-cols-[0.8fr_1.2fr] lg:gap-16">
        <SectionHeading title="A fix you can paste, not a link to a blog post">
          SiteShield reads your project to work out what you deploy with, then writes each fix in that
          stack&apos;s own terms. This one adds the headers an HDR001 finding asks for. Run the scan
          again and the report shows what changed: fixed, still open, or new.
        </SectionHeading>
        <Reveal delay={120} className="min-w-0">
          <Tabs defaultValue={headerFixes[0].label} className="min-w-0">
            <TabsList>
              {headerFixes.map((s) => (
                <TabsTrigger key={s.label} value={s.label} className="px-3">
                  {s.label}
                </TabsTrigger>
              ))}
            </TabsList>
            {headerFixes.map((s) => (
              <TabsContent key={s.label} value={s.label}>
                <CodeBlock code={s.code} file={s.file} className="bg-background" />
              </TabsContent>
            ))}
          </Tabs>
        </Reveal>
      </Container>
    </section>
  );
}

function Ci() {
  return (
    <section className="py-16 lg:py-24">
      <Container className="grid grid-cols-1 gap-10 lg:grid-cols-2 lg:items-center lg:gap-16">
        <SectionHeading title="Block the bad deploy before it merges">
          Drop SiteShield into a GitHub Action and it scans every pull request. Findings show up in the
          Security tab, and the gate fails the build on anything high or critical, so the problem never
          reaches your main branch.
        </SectionHeading>
        <Reveal delay={120}>
          <CiPipeline />
        </Reveal>
      </Container>
    </section>
  );
}

function Grades() {
  return (
    <section className="border-y bg-surface-low py-16 lg:py-24">
      <Container className="space-y-10">
        <SectionHeading title="How the grade is actually calculated">
          One number for the whole app, worked out the same way every time. No black box.
        </SectionHeading>
        <ScoreExplainer />
      </Container>
    </section>
  );
}

const cards = [
  { href: "/scan", icon: GlobeIcon, title: "Scan a site", body: "Paste any public URL and grade its live security from the browser." },
  { href: "/scan/code", icon: FileCode2Icon, title: "Scan your code", body: "Upload a project folder and read the source for the problems behind it." },
  { href: "/install", icon: TerminalIcon, title: "Run it locally", body: "Install from npm and run siteshield in your terminal or in CI." },
];

function RunItYourWay() {
  return (
    <section className="py-16 lg:py-24">
      <Container className="space-y-10">
        <SectionHeading title="Run it your way">Three ways in, one engine behind all of them.</SectionHeading>
        <div className="grid gap-4 sm:grid-cols-3">
          {cards.map((c, i) => (
            <Reveal key={c.href} delay={i * 110}>
              <Link
                href={c.href}
                className="group flex h-full flex-col gap-3 rounded-xl border bg-surface-low p-5 transition hover:-translate-y-0.5 hover:shadow-sm"
              >
                <span className="flex size-10 items-center justify-center rounded-lg bg-surface-mid text-primary-text">
                  <c.icon className="size-5" />
                </span>
                <span className="font-heading text-lg font-semibold">{c.title}</span>
                <span className="text-sm text-pretty text-muted-foreground">{c.body}</span>
                <span className="mt-auto inline-flex items-center gap-1 text-sm font-medium text-primary-text">
                  Open
                  <ArrowRightIcon className="size-4 transition group-hover:translate-x-0.5" />
                </span>
              </Link>
            </Reveal>
          ))}
        </div>
      </Container>
    </section>
  );
}
