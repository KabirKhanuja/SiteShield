# siteshield (CLI)

Audit a live website and the source code behind it in one pass, then get a single A–F grade
and copy-paste fixes for every finding.

The package is not published to npm yet. From a clone of this repo you can run it with:

```bash
npm install                                   # once, from the repo root

# live site + source code together
npm run siteshield -- scan https://example.com --src .

# only the source code (no network requests to a site)
npm run siteshield -- scan --src .

# only the live site
npm run siteshield -- scan https://example.com
```

Or call the entry directly (handy in CI):

```bash
node --import tsx packages/cli/src/cli.ts scan --src . --fail-on high
```

## Commands

| Command | What it does |
| --- | --- |
| `scan [url]` | Scan a live site, source code, or both |
| `verify <domain>` | Prove you own a domain (needed before any active checks) |

## Options

| Flag | Meaning |
| --- | --- |
| `--src <path>` | Folder to read source code from (omit to skip the code scan) |
| `--stack <names>` | Force stacks for fixes: `nextjs,express,nginx,vercel` (detected otherwise) |
| `--format <type>` | `text` (default), `json`, `sarif`, or `html` |
| `--min-severity <level>` | Hide findings below this level |
| `--fail-on <level>` | Exit 2 if any finding is at or above this level (CI gate) |
| `--only <ids>` | Run only these check ids, e.g. `--only HDR001,TLS001` |
| `--ignore <ids>` | Skip these check ids |
| `--baseline <file>` | Compare with an earlier JSON report (fixed / still open / new) |
| `--offline` | Skip the OSV.dev dependency lookup |
| `--passive` | Never run active checks, even on a verified domain |

Exit codes: `0` finished, `1` bad arguments or a runtime error, `2` the `--fail-on`
threshold was hit.

## Formats

- **text** — the default human-readable report.
- **json** — the full report; save it and pass it to `--baseline` on the next run.
- **sarif** — SARIF 2.1.0, so findings show up in GitHub code scanning.
- **html** — a self-contained pentest-style report (executive summary, risk rating, CVSS and
  OWASP per finding, remediation). Open it in a browser and print to PDF.

```bash
# save a baseline, fix things, then see what changed
node --import tsx packages/cli/src/cli.ts scan https://example.com --src . --format json > before.json
node --import tsx packages/cli/src/cli.ts scan https://example.com --src . --baseline before.json

# a shareable report
node --import tsx packages/cli/src/cli.ts scan --src . --format html > report.html
```

## Config file

Put a `siteshield.config.json` in the project root so nobody has to remember the flags.
Anything on the command line overrides it.

```json
{
  "url": "https://example.com",
  "src": ".",
  "stack": "nextjs",
  "failOn": "high",
  "ignore": ["CFG001"]
}
```

## Credits

The source rules started from [vibe guard](https://github.com/IAmUnbounded/vibe-guard) (MIT),
ported to TypeScript with the false positives cut down and rules added for public env vars,
unguarded routes and missing rate limits. Dependency advisories come from
[OSV.dev](https://osv.dev).
