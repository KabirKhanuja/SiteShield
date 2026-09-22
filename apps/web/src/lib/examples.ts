export type Snippet = {
  label: string;
  file: string;
  code: string;
};

export const headerFixes: Snippet[] = [
  {
    label: "Next.js",
    file: "next.config.ts",
    code: `const securityHeaders = [
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
  { key: "Content-Security-Policy", value: "default-src 'self'; frame-ancestors 'none'" },
];

export default {
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
};`,
  },
  {
    label: "Express",
    file: "server.ts",
    code: `import helmet from "helmet";

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: { defaultSrc: ["'self'"], frameAncestors: ["'none'"] },
    },
    strictTransportSecurity: { maxAge: 63072000, includeSubDomains: true, preload: true },
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
  })
);`,
  },
  {
    label: "nginx",
    file: "nginx.conf",
    code: `add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'none'" always;`,
  },
  {
    label: "Vercel",
    file: "vercel.json",
    code: `{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        { "key": "Strict-Transport-Security", "value": "max-age=63072000; includeSubDomains; preload" },
        { "key": "X-Content-Type-Options", "value": "nosniff" },
        { "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" },
        { "key": "Content-Security-Policy", "value": "default-src 'self'; frame-ancestors 'none'" }
      ]
    }
  ]
}`,
  },
];

export const usage: Snippet[] = [
  {
    label: "CLI",
    file: "terminal",
    code: `# live site and source code together
npx siteshield scan https://yoursite.com --src .

# only the code, no network requests
npx siteshield scan --src ./apps/api

# JSON for scripts, SARIF for GitHub code scanning
npx siteshield scan https://yoursite.com --src . --format sarif > results.sarif`,
  },
  {
    label: "Config file",
    file: "siteshield.config.json",
    code: `{
  "url": "https://yoursite.com",
  "src": ".",
  "stack": "nextjs",
  "failOn": "high",
  "ignore": ["CFG001"]
}`,
  },
  {
    label: "Library",
    file: "audit.ts",
    code: `import { scan } from "siteshield";

const report = await scan({ url: "https://yoursite.com", src: "." });

console.log(report.grade); // "B"
for (const finding of report.findings.filter((f) => f.status === "confirmed")) {
  console.log(finding.checkId, finding.title);
}`,
  },
  {
    label: "GitHub Actions",
    file: ".github/workflows/security.yml",
    code: `name: security
on: [pull_request]

jobs:
  siteshield:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npx siteshield scan --src . --fail-on high`,
  },
];
