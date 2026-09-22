import type { Metadata } from "next";
import { LockKeyholeIcon } from "lucide-react";
import { CodeBlock } from "@/components/site/code-block";
import { Command } from "@/components/site/command";
import { DocsMobileNav, DocsSidebar, type DocLink } from "@/components/site/docs-nav";
import { SiteFooter } from "@/components/site/site-footer";
import { SiteHeader } from "@/components/site/site-header";
import { checks } from "@/lib/checks";
import { usage } from "@/lib/examples";

export const metadata: Metadata = {
  title: "Documentation",
  description: "Install SiteShield, run your first scan, verify ownership and read your report.",
};

const sections: DocLink[] = [
  { id: "install", label: "Install" },
  { id: "first-scan", label: "Your first scan" },
  { id: "cli", label: "CLI reference" },
  { id: "config", label: "Config file" },
  { id: "checks", label: "Check reference" },
  { id: "ownership", label: "Ownership verification" },
  { id: "confirmed", label: "Confirmed findings" },
  { id: "grade", label: "How the grade works" },
  { id: "rescan", label: "Checking a fix" },
  { id: "ci", label: "Running in CI" },
  { id: "library", label: "Using it as a library" },
  { id: "credits", label: "Credits" },
];

const snippet = (label: string) => usage.find((u) => u.label === label)!;

export default function DocsPage() {
  return (
    <>
      <SiteHeader />
      <main className="mx-auto grid w-full max-w-6xl flex-1 grid-cols-1 gap-10 px-4 py-10 sm:px-6 lg:grid-cols-[13rem_1fr] lg:py-14">
        <DocsSidebar links={sections} />
        <article className="min-w-0 max-w-3xl space-y-16">
          <header className="space-y-4">
            <h1 className="font-heading text-4xl font-semibold tracking-tight">Documentation</h1>
            <p className="text-lg text-pretty text-muted-foreground">
              Everything you need to scan a site and its code, understand the report, and fix what it
              finds. SiteShield is still being built and is not on npm yet, so this page describes how
              version 0.1 will work when it ships.
            </p>
            <DocsMobileNav links={sections} />
          </header>

          <Section id="install" title="Install">
            <p>
              You do not have to install anything to try it. npx downloads the latest version, runs it
              and cleans up:
            </p>
            <Command value="npx siteshield scan https://yoursite.com" />
            <p>
              If you want the same version for everyone on the team and in CI, add it as a dev
              dependency instead:
            </p>
            <Command value="npm install --save-dev siteshield" />
            <p className="text-sm text-muted-foreground">
              Requires Node 20 or newer. Works on macOS, Linux and Windows.
            </p>
          </Section>

          <Section id="first-scan" title="Your first scan">
            <p>
              Run it from the root of your project and pass the address where that project is deployed.
              The <Code>--src</Code> flag points at the code to read.
            </p>
            <Command value="npx siteshield scan https://yoursite.com --src ." />
            <p>
              The first run only does passive checks on the live site, meaning it reads what any visitor
              could read: certificates, headers, DNS records and public JavaScript. That takes about
              thirty seconds. To unlock the active checks, verify ownership first (see{" "}
              <a href="#ownership" className="text-primary-text underline underline-offset-4">
                Ownership verification
              </a>
              ).
            </p>
            <p>You can also scan just one side:</p>
            <CodeBlock
              file="terminal"
              code={`# only the live site
npx siteshield scan https://yoursite.com

# only the code, no network requests at all
npx siteshield scan --src .`}
            />
          </Section>

          <Section id="cli" title="CLI reference">
            <Table
              head={["Command or flag", "What it does"]}
              rows={[
                ["scan [url]", "Scan a live site, source code, or both."],
                ["--src <path>", "Folder to read source code from. Leave it out to skip the code scan."],
                ["--stack <name>", "Force the stack used for fixes: nextjs, express, nginx or vercel. Detected automatically otherwise."],
                ["--format <type>", "text (default), json, or sarif for GitHub code scanning."],
                ["--min-severity <level>", "Hide findings below low, medium, high or critical."],
                ["--fail-on <level>", "Exit with code 2 if any finding is at or above this level. Use it in CI."],
                ["--only <ids>", "Run only these checks, for example --only HDR001,TLS001."],
                ["--ignore <ids>", "Skip these checks."],
                ["--baseline <file>", "Compare with an earlier JSON report and show what was fixed, what is still open and what is new."],
                ["--passive", "Never run active checks, even on a verified domain."],
                ["verify <domain>", "Get a verification token, then confirm it once it is published."],
              ]}
            />
            <p className="text-sm text-muted-foreground">
              Exit codes: <Code>0</Code> scan finished, <Code>1</Code> bad arguments or a runtime error,{" "}
              <Code>2</Code> the <Code>--fail-on</Code> threshold was hit.
            </p>
          </Section>

          <Section id="config" title="Config file">
            <p>
              Put a <Code>siteshield.config.json</Code> in the project root so nobody has to remember the
              flags. Anything passed on the command line wins over the file.
            </p>
            <CodeBlock code={snippet("Config file").code} file={snippet("Config file").file} />
            <Table
              head={["Field", "Meaning"]}
              rows={[
                ["url", "Address of the deployed site."],
                ["src", "Path to the code, relative to the config file."],
                ["stack", "Same values as --stack."],
                ["failOn", "Same as --fail-on."],
                ["ignore", "Check IDs to skip. Add a note in your repo about why."],
              ]}
            />
          </Section>

          <Section id="checks" title="Check reference">
            <p>
              Every finding carries one of these IDs. Checks marked with a lock only run after ownership
              is verified, because they send test traffic rather than just reading.
            </p>
            <div className="overflow-x-auto rounded-lg border">
              <table className="w-full text-left text-sm">
                <thead className="bg-surface-mid text-xs text-muted-foreground">
                  <tr>
                    <th className="px-3 py-2.5 font-medium">ID</th>
                    <th className="px-3 py-2.5 font-medium">Layer</th>
                    <th className="px-3 py-2.5 font-medium">What it looks for</th>
                  </tr>
                </thead>
                <tbody className="divide-y">
                  {checks.map((c) => (
                    <tr key={c.id} className="align-top">
                      <td className="px-3 py-3 font-mono text-xs whitespace-nowrap">
                        <span className="inline-flex items-center gap-1.5">
                          {c.id}
                          {c.mode === "verified" ? (
                            <LockKeyholeIcon className="size-3 text-primary-text" aria-label="Needs ownership check" />
                          ) : null}
                        </span>
                      </td>
                      <td className="px-3 py-3 whitespace-nowrap text-muted-foreground">
                        {c.layer === "live" ? "Live site" : "Source"}
                      </td>
                      <td className="px-3 py-3">
                        <p className="font-medium">{c.name}</p>
                        <p className="mt-0.5 text-pretty text-muted-foreground">{c.question}</p>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Section>

          <Section id="ownership" title="Ownership verification">
            <p>
              Rate limit tests, exposed file probes and injection probes send traffic that a server owner
              could reasonably read as an attack. Doing that to a site you do not own, without written
              permission, is illegal in most places. SiteShield will not run them until you prove control
              of the domain.
            </p>
            <CodeBlock
              file="terminal"
              code={`$ npx siteshield verify yoursite.com

Add one of these, then run the same command again:

  DNS   _siteshield.yoursite.com  TXT  "siteshield-verify=7f3c9a1e52b84d06"
  HTTP  https://yoursite.com/.well-known/siteshield.txt  containing  7f3c9a1e52b84d06`}
            />
            <p>
              Once it finds the token, the domain is marked verified on your machine for 30 days. Every
              active request is logged with its time, URL and response code in{" "}
              <Code>.siteshield/audit.log</Code>, so you can show exactly what was sent.
            </p>
            <p>
              Active checks are capped. The rate limit test sends at most 30 requests to one endpoint,
              and the injection probes only use harmless marker strings, never payloads that write,
              delete or execute anything.
            </p>
          </Section>

          <Section id="confirmed" title="Confirmed findings">
            <p>Every finding has one of three statuses:</p>
            <Table
              head={["Status", "Meaning"]}
              rows={[
                ["Confirmed", "The code scan and the live scan found the same problem. Fix these first."],
                ["Code only", "Found in the code, not seen on the live site. It may not be deployed yet, or the active check that would confirm it was not allowed to run."],
                ["Live only", "Seen on the live site with no matching code. Often a hosting, CDN or DNS setting rather than something in the repo."],
              ]}
            />
            <p>
              Some examples of pairs: a hardcoded key (SEC001) that also shows up in your public
              JavaScript (BND001), a CORS setting in code (COR002) that the live API really does send
              (COR001), and a login route with no limiter (RTL002) that keeps accepting requests during
              the live test (RTL001).
            </p>
          </Section>

          <Section id="grade" title="How the grade works">
            <p>
              Each scan starts at 100 points. Findings take points off by severity. A confirmed finding
              costs one and a half times as much, because it is known to be real.
            </p>
            <Table
              head={["Severity", "Points off", "If confirmed"]}
              rows={[
                ["Critical", "25", "37.5"],
                ["High", "12", "18"],
                ["Medium", "5", "7.5"],
                ["Low", "1", "1.5"],
              ]}
            />
            <p>
              The score maps to a letter: A from 90, B from 75, C from 60, D from 40, and F below that.
              One rule overrides the maths: any confirmed critical finding caps the grade at D. A site
              leaking a live secret key should never show a B.
            </p>
          </Section>

          <Section id="rescan" title="Checking a fix">
            <p>
              Save a report as JSON, apply your fixes, then scan again against that report. SiteShield
              matches findings across both runs and tells you what changed.
            </p>
            <CodeBlock
              file="terminal"
              code={`npx siteshield scan https://yoursite.com --src . --format json > before.json

# apply the fixes, deploy

npx siteshield scan https://yoursite.com --src . --baseline before.json`}
            />
          </Section>

          <Section id="ci" title="Running in CI">
            <p>
              Scanning only the code needs no verification and no network access to your site, so it is
              safe to run on every pull request. This workflow fails the check if anything high or
              critical turns up.
            </p>
            <CodeBlock code={snippet("GitHub Actions").code} file={snippet("GitHub Actions").file} />
            <p>
              Use <Code>--format sarif</Code> and the upload SARIF action if you want findings to show up
              inline on the pull request.
            </p>
          </Section>

          <Section id="library" title="Using it as a library">
            <p>The CLI is a thin wrapper around the same function you can import:</p>
            <CodeBlock code={snippet("Library").code} file={snippet("Library").file} />
          </Section>

          <Section id="credits" title="Credits">
            <p>
              The source code rules and the input tracing started from{" "}
              <a className="text-primary-text underline underline-offset-4" href="https://github.com/IAmUnbounded/vibe-guard">
                vibe guard
              </a>{" "}
              by Unbounded, released under the MIT license. SiteShield ported them to TypeScript, cut
              down false positives, and added the rules for public env vars, unguarded routes and missing
              rate limits. Dependency advisories come from{" "}
              <a className="text-primary-text underline underline-offset-4" href="https://osv.dev">
                OSV.dev
              </a>
              .
            </p>
          </Section>
        </article>
      </main>
      <SiteFooter />
    </>
  );
}

function Section({ id, title, children }: { id: string; title: string; children: React.ReactNode }) {
  return (
    <section id={id} className="space-y-4 leading-relaxed">
      <h2 className="border-b pb-2 font-heading text-2xl font-semibold tracking-tight">
        <a href={`#${id}`} className="hover:text-primary-text">
          {title}
        </a>
      </h2>
      {children}
    </section>
  );
}

function Code({ children }: { children: React.ReactNode }) {
  return <code className="rounded-xs bg-surface-mid px-1.5 py-0.5 font-mono text-[0.85em]">{children}</code>;
}

function Table({ head, rows }: { head: string[]; rows: string[][] }) {
  return (
    <div className="overflow-x-auto rounded-lg border">
      <table className="w-full text-left text-sm">
        <thead className="bg-surface-mid text-xs text-muted-foreground">
          <tr>
            {head.map((h) => (
              <th key={h} className="px-3 py-2.5 font-medium">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y">
          {rows.map((r) => (
            <tr key={r[0]} className="align-top">
              {r.map((cell, i) => (
                <td
                  key={i}
                  className={i === 0 ? "px-3 py-3 font-mono text-xs whitespace-nowrap" : "px-3 py-3 text-pretty"}
                >
                  {cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
