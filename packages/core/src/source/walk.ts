import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";

/** A source file read into memory, with a path relative to the scan root. */
export type SourceFile = {
  /** Always forward slashed, so findings read the same on every OS. */
  path: string;
  content: string;
  lines: string[];
};

// Reading build output, dependencies or the .git store would only produce noise and false
// positives (a secret in a vendored dependency is not the user's to fix here).
const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  ".next",
  ".nuxt",
  ".svelte-kit",
  "dist",
  "build",
  "out",
  "coverage",
  ".turbo",
  ".cache",
  "vendor",
  ".venv",
  "venv",
  "__pycache__",
  ".idea",
  ".vscode",
  "__tests__",
  "__mocks__",
  "e2e",
  ".storybook",
]);

// Test files and generated files are skipped by default: scanning them mostly produces noise
// (a test fixture full of deliberately insecure code is not a finding to fix). A project that
// really wants them scanned can point --src straight at that folder.
const SKIP_FILE = /(\.(test|spec)\.[tj]sx?|\.min\.js|\.d\.ts|\.map)$/i;

// Only text we can reasonably analyse. Lockfiles and env files are kept because the
// dependency and secret checks need them.
const SCAN_EXTENSIONS = new Set([
  ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro",
  ".py", ".rb", ".php", ".go", ".java", ".cs", ".json", ".yml", ".yaml",
  ".toml", ".env", ".config", ".conf", ".sh", ".sql", ".html",
]);

const KEEP_BY_NAME = new Set([
  ".env", "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
  "requirements.txt", "Gemfile.lock", "composer.lock", "go.mod", "go.sum",
  "next.config.js", "next.config.ts", "nginx.conf", "vercel.json", "Dockerfile",
]);

const MAX_FILE_BYTES = 1_000_000; // 1 MB: a bigger text file is almost always generated.
const MAX_FILES = 5000; // A guard so pointing it at a huge monorepo cannot hang the scan.

function shouldRead(name: string): boolean {
  if (SKIP_FILE.test(name)) return false;
  if (KEEP_BY_NAME.has(name)) return true;
  if (name.startsWith(".env.")) return true; // .env.local, .env.production, ...
  const dot = name.lastIndexOf(".");
  if (dot <= 0) return false;
  return SCAN_EXTENSIONS.has(name.slice(dot).toLowerCase());
}

/**
 * Reads every analysable text file under root, skipping dependencies and build output.
 * Everything is loaded once here and shared by the checks, so each file is read from disk
 * a single time.
 */
export function walkSource(root: string): SourceFile[] {
  const files: SourceFile[] = [];

  const visit = (dir: string) => {
    if (files.length >= MAX_FILES) return;
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return; // Unreadable directory (permissions, a broken symlink): skip it.
    }
    for (const name of entries) {
      if (files.length >= MAX_FILES) return;
      const full = join(dir, name);
      let stat;
      try {
        stat = statSync(full);
      } catch {
        continue;
      }
      if (stat.isDirectory()) {
        if (SKIP_DIRS.has(name) || name.startsWith(".") && name !== ".github") continue;
        visit(full);
      } else if (stat.isFile() && stat.size <= MAX_FILE_BYTES && shouldRead(name)) {
        let content: string;
        try {
          content = readFileSync(full, "utf8");
        } catch {
          continue;
        }
        // A NUL byte in the first chunk means it is really binary despite the extension.
        if (content.includes("\u0000")) continue;
        files.push({
          path: relative(root, full).split(sep).join("/"),
          content,
          lines: content.split(/\r?\n/),
        });
      }
    }
  };

  visit(root);
  return files;
}

/**
 * Decides, from a forward-slashed relative path, whether a file is worth scanning. Shares the
 * skip rules with the disk walk so an uploaded tree is filtered the same way as one on disk.
 */
export function pathIsScannable(path: string): boolean {
  const parts = path.split("/").filter(Boolean);
  const name = parts[parts.length - 1];
  if (!name) return false;
  for (const seg of parts.slice(0, -1)) {
    if (SKIP_DIRS.has(seg)) return false;
    if (seg.startsWith(".") && seg !== ".github") return false;
  }
  return shouldRead(name);
}

/**
 * Builds SourceFiles from files uploaded in memory (for example from a browser folder picker),
 * applying the same filters, size cap and binary guard as {@link walkSource}.
 */
export function sourceFilesFromUploads(inputs: { path: string; content: string }[]): SourceFile[] {
  const files: SourceFile[] = [];
  for (const input of inputs) {
    if (files.length >= MAX_FILES) break;
    const path = input.path.split(sep).join("/").replace(/^\.?\/+/, "");
    if (!pathIsScannable(path)) continue;
    const content = input.content;
    if (content.length > MAX_FILE_BYTES) continue;
    if (content.includes("\u0000")) continue; // really binary despite the extension
    files.push({ path, content, lines: content.split(/\r?\n/) });
  }
  return files;
}

/** Turns a character offset in a file's content into a 1-based line and column. */
export function positionAt(content: string, index: number): { line: number; column: number } {
  let line = 1;
  let last = -1;
  for (let i = 0; i < index; i++) {
    if (content[i] === "\n") {
      line++;
      last = i;
    }
  }
  return { line, column: index - last };
}
