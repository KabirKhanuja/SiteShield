"use client";

import { useRef, useState } from "react";
import { DownloadIcon, FolderUpIcon, LoaderCircleIcon, ShieldIcon } from "lucide-react";
import { ReportResults } from "@/components/scan/report-view";
import { Button } from "@/components/ui/button";
import { ApiError, scanSource, type Report, type UploadedFile } from "@/lib/api";
import { SAMPLE_CODE } from "@/lib/sample-code";
import { cn } from "@/lib/utils";

// Kept in step with the engine's walker: directories that are only noise, and the file types
// worth reading. Filtering here keeps a node_modules folder from being uploaded by accident.
const SKIP_DIRS = new Set([
  "node_modules", ".git", ".next", ".nuxt", ".svelte-kit", "dist", "build", "out",
  "coverage", ".turbo", ".cache", "vendor", ".venv", "venv", "__pycache__", ".idea", ".vscode",
]);
const SCAN_EXT = new Set([
  "js", "jsx", "ts", "tsx", "mjs", "cjs", "vue", "svelte", "astro", "py", "rb", "php", "go",
  "java", "cs", "json", "yml", "yaml", "toml", "env", "config", "conf", "sh", "sql", "html",
]);
const KEEP_NAME = new Set([
  ".env", "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt",
  "Gemfile.lock", "composer.lock", "go.mod", "go.sum", "next.config.js", "next.config.ts",
  "nginx.conf", "vercel.json", "Dockerfile",
]);

const MAX_FILES = 2000;
const MAX_FILE_BYTES = 1_000_000;
const MAX_TOTAL_BYTES = 10_000_000;

function scannable(path: string): boolean {
  const parts = path.split("/").filter(Boolean);
  const name = parts[parts.length - 1] ?? "";
  if (parts.slice(0, -1).some((p) => SKIP_DIRS.has(p) || (p.startsWith(".") && p !== ".github"))) return false;
  if (KEEP_NAME.has(name) || name.startsWith(".env.")) return true;
  const ext = name.includes(".") ? name.slice(name.lastIndexOf(".") + 1).toLowerCase() : "";
  return SCAN_EXT.has(ext);
}

async function readFiles(fileList: FileList): Promise<{ files: UploadedFile[]; skipped: number }> {
  const files: UploadedFile[] = [];
  let total = 0;
  let skipped = 0;
  for (const file of Array.from(fileList)) {
    if (files.length >= MAX_FILES) break;
    const path = file.webkitRelativePath || file.name;
    if (!scannable(path) || file.size > MAX_FILE_BYTES) {
      skipped++;
      continue;
    }
    if (total + file.size > MAX_TOTAL_BYTES) break;
    const content = await file.text();
    if (content.includes("\u0000")) {
      skipped++;
      continue;
    }
    total += file.size;
    files.push({ path, content });
  }
  return { files, skipped };
}

export function CodeScan() {
  const folderInput = useRef<HTMLInputElement>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [scanned, setScanned] = useState(0);
  const [pending, setPending] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [offline, setOffline] = useState(false);

  async function run(files: UploadedFile[], label: string) {
    if (files.length === 0) {
      setError("No scannable code was found. Pick a project folder with source files in it.");
      return;
    }
    setError(null);
    setReport(null);
    setPending(true);
    setStatus(`Scanning ${files.length} ${files.length === 1 ? "file" : "files"} from ${label}${offline ? "" : ", checking dependencies against OSV.dev"}`);
    try {
      const res = await scanSource(files, offline);
      setReport(res.report);
      setScanned(res.scanned);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "The scan failed. Is the API running?");
    } finally {
      setPending(false);
      setStatus(null);
    }
  }

  async function onPick(e: React.ChangeEvent<HTMLInputElement>) {
    const list = e.target.files;
    if (!list || list.length === 0) return;
    setStatus("Reading files");
    const { files } = await readFiles(list);
    await run(files, "your project");
    e.target.value = "";
  }

  function downloadJson() {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "siteshield-report.json";
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="space-y-8">
      <div className="space-y-4 rounded-xl border bg-surface-low p-5">
        <div className="flex flex-wrap gap-3">
          <Button onClick={() => folderInput.current?.click()} disabled={pending} className="h-10">
            {pending ? <LoaderCircleIcon className="animate-spin" data-icon="inline-start" /> : <FolderUpIcon data-icon="inline-start" />}
            Choose a project folder
          </Button>
          <Button variant="outline" onClick={() => run(SAMPLE_CODE, "the sample app")} disabled={pending} className="h-10">
            <ShieldIcon data-icon="inline-start" />
            Scan the sample vulnerable app
          </Button>
          <input
            ref={folderInput}
            type="file"
            multiple
            onChange={onPick}
            className="hidden"
            {...({ webkitdirectory: "", directory: "" } as Record<string, string>)}
          />
        </div>
        <label className="flex items-center gap-2 text-sm text-muted-foreground">
          <input type="checkbox" checked={offline} onChange={(e) => setOffline(e.target.checked)} className="size-4" />
          Skip the OSV.dev dependency lookup (offline)
        </label>
        <p className="text-sm text-muted-foreground">
          Your code is read in the browser and sent once to the scanner. Nothing is stored, and the
          report is not saved or shared. Dependencies, build output and binaries are skipped
          automatically.
        </p>
        {status ? (
          <p className="flex items-center gap-2 text-sm text-primary-text">
            <LoaderCircleIcon className="size-4 animate-spin" /> {status}
          </p>
        ) : null}
        {error ? (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        ) : null}
      </div>

      {report ? (
        <div className={cn("space-y-6")}>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-sm text-muted-foreground">
              Scanned {scanned} {scanned === 1 ? "file" : "files"}.
            </p>
            <Button variant="outline" onClick={downloadJson}>
              <DownloadIcon data-icon="inline-start" />
              Download JSON
            </Button>
          </div>
          <ReportResults report={report} />
        </div>
      ) : null}
    </div>
  );
}
