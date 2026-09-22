import Link from "next/link";
import { ArrowRightIcon, LockKeyholeIcon } from "lucide-react";
import { CodeBlock } from "@/components/site/code-block";
import { Command } from "@/components/site/command";
import { GradeTile, type Grade } from "@/components/site/grade";
import { ReportPreview } from "@/components/site/report-preview";
import { SeverityLabel, StatusLabel } from "@/components/site/severity";
import { SiteFooter } from "@/components/site/site-footer";
import { SiteHeader } from "@/components/site/site-header";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { liveChecks, sourceChecks, type Check } from "@/lib/checks";
import { headerFixes, usage } from "@/lib/examples";

const SCAN_COMMAND = "npx siteshield scan https://yoursite.com --src .";

export default function Home() {
  return (
    <>
      <SiteHeader />
      <main className="flex-1">
        <Hero />
        <Checks />
        <Confirmation />
        <Fixes />
        <Ownership />
        <Grades />
        <Usage />
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
    <div className="max-w-2xl space-y-3">
      <h2 className="font-heading text-3xl font-semibold tracking-tight text-balance sm:text-[34px]">
        {title}
      </h2>
      {children ? <div className="text-pretty text-muted-foreground">{children}</div> : null}
    </div>
  );
}

function Hero() {
  return (
    <section className="border-b">
      <Container className="grid grid-cols-1 gap-12 py-14 lg:grid-cols-[1.05fr_1fr] lg:items-center lg:py-20">
        <div className="space-y-7">
          <h1 className="font-heading text-4xl leading-[1.08] font-semibold tracking-tight text-balance sm:text-5xl lg:text-[56px]">
            Audit the site you shipped and the code behind it, in one pass.
          </h1>
          <p className="max-w-xl text-lg text-pretty text-muted-foreground">
            SiteShield checks your live website and your source code together. When both point at the
            same problem, the finding is marked confirmed. Every finding comes with the fix for your
            stack, and a second scan tells you whether the fix actually worked.
          </p>
          <div className="max-w-xl space-y-3">
            <Command value={SCAN_COMMAND} />
            <p className="text-sm text-muted-foreground">
              Needs Node 20 or newer. The npm package is not published yet, so treat this as the
              interface we are building toward.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button asChild size="lg" className="px-4">
              <Link href="/docs">
                Read the docs
                <ArrowRightIcon data-icon="inline-end" />
              </Link>
            </Button>
            <Button asChild size="lg" variant="outline" className="px-4">
              <Link href="#checks">See what it checks</Link>
            </Button>
          </div>
        </div>
        <ReportPreview />
      </Container>
    </section>
  );
}

function CheckList({ title, items }: { title: string; items: Check[] }) {
  return (
    <div>
      <h3 className="border-b pb-3 font-heading text-lg font-semibold">{title}</h3>
      <ul className="divide-y">
        {items.map((c) => (
          <li key={c.id} className="grid grid-cols-[4.25rem_1fr] gap-x-3 py-4">
            <span className="pt-0.5 font-mono text-xs text-muted-foreground">{c.id}</span>
            <div className="space-y-1">
              <p className="flex flex-wrap items-center gap-x-2 gap-y-1 font-medium">
                {c.name}
                {c.mode === "verified" ? (
                  <span className="inline-flex items-center gap-1 text-xs font-normal text-primary-text">
                    <LockKeyholeIcon className="size-3" aria-hidden />
                    after ownership check
                  </span>
                ) : null}
              </p>
              <p className="text-sm text-pretty text-muted-foreground">{c.question}</p>
              {c.pairsWith ? (
                <p className="font-mono text-[11px] text-muted-foreground">
                  confirms with {c.pairsWith.join(", ")}
                </p>
              ) : null}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

function Checks() {
  return (
    <section id="checks" className="py-16 lg:py-24">
      <Container className="space-y-12">
        <SectionHeading title="Nineteen checks across two layers">
          Checks that only read public information run on any site. The ones that send test traffic
          wait until you prove the site is yours.
        </SectionHeading>
        <div className="grid grid-cols-1 gap-12 lg:grid-cols-2 lg:gap-16">
          <CheckList title="On the live site" items={liveChecks} />
          <CheckList title="In your source code" items={sourceChecks} />
        </div>
      </Container>
    </section>
  );
}

function Confirmation() {
  return (
    <section className="border-y bg-surface-low py-16 lg:py-24">
      <Container className="space-y-10">
        <SectionHeading title="When the code and the site agree, it is not a guess">
          Scanners that read only code flag things that never reach production. Scanners that probe
          only the site cannot tell you which line to change. SiteShield runs both and matches the
          results, so you know what is real and where it lives.
        </SectionHeading>

        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <div className="overflow-hidden rounded-lg border bg-background">
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
          </div>
          <div className="overflow-hidden rounded-lg border bg-background">
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
          </div>
        </div>

        {/* The verdict, marked the same way as a row in the report rather than as a callout box. */}
        <div className="flex flex-col gap-2 sm:flex-row sm:gap-6">
          <div className="flex shrink-0 items-start gap-4">
            <StatusLabel status="confirmed" />
            <SeverityLabel severity="high" className="pt-0.5" />
          </div>
          <p className="text-sm text-pretty text-muted-foreground">
            The config reflects any origin and the live API proves it. A page on any other domain can
            read <span className="font-mono text-foreground">/api/me</span> as your logged in user.
            The fix goes on line 12.
          </p>
        </div>
      </Container>
    </section>
  );
}

function Fixes() {
  return (
    <section id="fixes" className="py-16 lg:py-24">
      <Container className="grid grid-cols-1 gap-10 lg:grid-cols-[0.8fr_1.2fr] lg:gap-16">
        <div className="space-y-6">
          <SectionHeading title="A fix you can paste, not a link to a blog post">
            SiteShield reads your project to work out what you deploy with, then writes each fix in
            that stack&apos;s own terms. This one adds the headers an HDR001 finding asks for.
          </SectionHeading>
          <p className="text-sm text-muted-foreground">
            After you apply it, run the scan again. The report shows what changed since the last run:
            fixed, still open, or new.
          </p>
        </div>
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
              <CodeBlock code={s.code} file={s.file} />
            </TabsContent>
          ))}
        </Tabs>
      </Container>
    </section>
  );
}

function Ownership() {
  const steps = [
    {
      title: "Ask for a token",
      body: "Run siteshield verify with your domain. You get a random token that belongs to this site and this machine.",
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

  return (
    <section className="border-y bg-surface-low py-16 lg:py-24">
      <Container className="grid grid-cols-1 gap-10 lg:grid-cols-2 lg:gap-16">
        <SectionHeading title="It will not probe a site you do not own">
          Sending login attempts or test payloads to someone else&apos;s server without permission is
          an offence in most countries, including under the IT Act in India. So SiteShield asks for
          proof first, the same way search consoles and certificate authorities do.
        </SectionHeading>
        <div className="space-y-6">
          <ol className="space-y-5">
            {steps.map((s, i) => (
              <li key={s.title} className="grid grid-cols-[2rem_1fr] gap-3">
                <span className="flex size-8 items-center justify-center rounded-sm bg-primary-container font-heading text-sm font-semibold text-on-primary-container">
                  {i + 1}
                </span>
                <div className="space-y-1 pt-1">
                  <p className="font-medium">{s.title}</p>
                  <p className="text-sm text-pretty text-muted-foreground">{s.body}</p>
                </div>
              </li>
            ))}
          </ol>
          <CodeBlock
            file="DNS record"
            code={`_siteshield.yoursite.com.  TXT  "siteshield-verify=7f3c9a1e52b84d06"`}
          />
        </div>
      </Container>
    </section>
  );
}

const gradeScale: { grade: Grade; range: string; meaning: string }[] = [
  { grade: "A", range: "90 to 100", meaning: "Nothing above low severity. Keep scanning in CI." },
  { grade: "B", range: "75 to 89", meaning: "Solid, with a few gaps worth closing this sprint." },
  { grade: "C", range: "60 to 74", meaning: "Real exposure. Start with anything confirmed." },
  { grade: "D", range: "40 to 59", meaning: "Serious issues, or any confirmed critical finding." },
  { grade: "F", range: "below 40", meaning: "Stop and fix before the next deploy." },
];

function Grades() {
  return (
    <section className="py-16 lg:py-24">
      <Container className="space-y-10">
        <SectionHeading title="One grade for the whole app">
          Every scan starts at 100. Each finding takes points off by severity, and confirmed findings
          count one and a half times. A confirmed critical finding caps the grade at D, however clean
          the rest is.
        </SectionHeading>
        <ol className="grid gap-px overflow-hidden rounded-lg border bg-border sm:grid-cols-5">
          {gradeScale.map((g) => (
            <li key={g.grade} className="flex gap-4 bg-background p-4 sm:flex-col">
              <GradeTile grade={g.grade} className="size-12 shrink-0 text-2xl" />
              <div className="space-y-1">
                <p className="font-mono text-xs text-muted-foreground">{g.range}</p>
                <p className="text-sm text-pretty">{g.meaning}</p>
              </div>
            </li>
          ))}
        </ol>
      </Container>
    </section>
  );
}

function Usage() {
  return (
    <section className="border-t bg-surface-low py-16 lg:py-24">
      <Container className="grid grid-cols-1 gap-10 lg:grid-cols-[0.8fr_1.2fr] lg:gap-16">
        <div className="space-y-6">
          <SectionHeading title="Run it wherever you already work">
            From a terminal with npx, from a config file checked into the repo, as a library inside
            your own tooling, or on every pull request.
          </SectionHeading>
          <Button asChild variant="outline" className="px-4">
            <Link href="/docs">
              Full documentation
              <ArrowRightIcon data-icon="inline-end" />
            </Link>
          </Button>
        </div>
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
              <CodeBlock code={s.code} file={s.file} className="bg-background" />
            </TabsContent>
          ))}
        </Tabs>
      </Container>
    </section>
  );
}
