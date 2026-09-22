export type CheckMode = "passive" | "verified";
export type Layer = "live" | "source";

export type Check = {
  id: string;
  layer: Layer;
  name: string;
  question: string;
  mode: CheckMode;
  // Checks on the other layer that can confirm this one.
  pairsWith?: string[];
};

export const checks: Check[] = [
  {
    id: "TLS001",
    layer: "live",
    name: "Certificate and TLS",
    question:
      "Is the certificate valid and trusted, and when does it expire? Are TLS 1.0 and 1.1 still accepted? Is HSTS set?",
    mode: "passive",
  },
  {
    id: "HDR001",
    layer: "live",
    name: "Security headers",
    question:
      "Does the site send Content Security Policy, frame protection, Referrer Policy and Permissions Policy, and are they strict enough to matter?",
    mode: "passive",
  },
  {
    id: "CKE001",
    layer: "live",
    name: "Cookie flags",
    question: "Are session cookies marked Secure, HttpOnly and SameSite?",
    mode: "passive",
  },
  {
    id: "DNS001",
    layer: "live",
    name: "Email authentication",
    question:
      "Do SPF, DKIM and DMARC records exist, so nobody can send mail that looks like it came from your domain?",
    mode: "passive",
  },
  {
    id: "COR001",
    layer: "live",
    name: "Live CORS policy",
    question: "Which origins does your API actually allow, and does it allow credentials with them?",
    mode: "passive",
    pairsWith: ["COR002"],
  },
  {
    id: "BND001",
    layer: "live",
    name: "Secrets in shipped JavaScript",
    question: "Do the JavaScript files your site sends to browsers contain API keys or tokens?",
    mode: "passive",
    pairsWith: ["SEC001", "PUB001"],
  },
  {
    id: "VER001",
    layer: "live",
    name: "Outdated software",
    question:
      "Which framework or CMS version is the site running, and does that version have known CVEs?",
    mode: "passive",
    pairsWith: ["DEP001"],
  },
  {
    id: "EXP001",
    layer: "live",
    name: "Exposed files",
    question:
      "Can anyone download .env, .git, backup archives, source maps or debug pages from the site?",
    mode: "verified",
    pairsWith: ["SEC001"],
  },
  {
    id: "RTL001",
    layer: "live",
    name: "Rate limiting",
    question:
      "Does the login, signup or API endpoint start refusing requests after a burst? We send a small, capped number.",
    mode: "verified",
    pairsWith: ["RTL002"],
  },
  {
    id: "INJ001",
    layer: "live",
    name: "Injection surface",
    question:
      "Does the site reflect a harmless marker string back unescaped, or leak SQL errors? No destructive payloads, ever.",
    mode: "verified",
    pairsWith: ["INJ002", "XSS001"],
  },
  {
    id: "SEC001",
    layer: "source",
    name: "Hardcoded secrets",
    question: "Are API keys, passwords, private keys or tokens written directly into the code or committed .env files?",
    mode: "passive",
  },
  {
    id: "PUB001",
    layer: "source",
    name: "Secrets in public env vars",
    question:
      "Is a secret stored in a NEXT_PUBLIC_ or VITE_ variable, which the build copies straight into the browser bundle?",
    mode: "passive",
  },
  {
    id: "DEP001",
    layer: "source",
    name: "Vulnerable dependencies",
    question: "Does your lockfile pin any package version with a published advisory? Looked up against OSV.dev.",
    mode: "passive",
  },
  {
    id: "AUT001",
    layer: "source",
    name: "Routes with no auth check",
    question:
      "Which API routes, route handlers and server actions change data without checking who is asking?",
    mode: "passive",
  },
  {
    id: "RTL002",
    layer: "source",
    name: "Auth routes with no limiter",
    question: "Do login, signup and password reset routes run without any rate limiting middleware?",
    mode: "passive",
  },
  {
    id: "COR002",
    layer: "source",
    name: "Permissive CORS config",
    question: "Does the code allow every origin, or reflect the request origin while sending credentials?",
    mode: "passive",
  },
  {
    id: "INJ002",
    layer: "source",
    name: "Untrusted input in dangerous calls",
    question:
      "Does request data flow into SQL strings, shell commands, eval, redirects or file paths?",
    mode: "passive",
  },
  {
    id: "XSS001",
    layer: "source",
    name: "Unsafe HTML sinks",
    question: "Is dangerouslySetInnerHTML or innerHTML fed with data that did not pass through a sanitizer?",
    mode: "passive",
  },
  {
    id: "CFG001",
    layer: "source",
    name: "Unsafe settings",
    question:
      "Is TLS verification switched off, JWT verification skipped, or MD5 and SHA1 used for passwords?",
    mode: "passive",
  },
];

export const liveChecks = checks.filter((c) => c.layer === "live");
export const sourceChecks = checks.filter((c) => c.layer === "source");
