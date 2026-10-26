import type { Finding, Remediation, SourceLocation, Stack } from "../types.ts";
import { positionAt, type SourceFile } from "./walk.ts";

export type PackageJson = {
  path: string;
  data: {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
    [key: string]: unknown;
  };
};

export type SourceContext = {
  root: string;
  files: SourceFile[];
  /** package.json files found anywhere in the tree, parsed. */
  packages: PackageJson[];
  /** Stacks detected from the files, used to route and filter remediation. */
  stacks: Stack[];
  offline: boolean;
  signal?: AbortSignal;
};

export type SourceCheck = {
  id: string;
  run(ctx: SourceContext): Promise<Finding[]> | Finding[];
};

/** Fills in the fields every source finding shares, so each check stays short. */
export function codeFinding(
  f: Omit<Finding, "layer" | "status"> & { status?: Finding["status"] },
): Finding {
  return { status: "code", ...f, layer: "source" };
}

/** Builds a source finding from a regex match inside a file, computing its line and column. */
export function findingAt(
  file: SourceFile,
  index: number,
  f: Omit<Finding, "layer" | "status" | "source" | "location"> & {
    snippet?: string;
  },
): Finding {
  const { line, column } = positionAt(file.content, index);
  const snippet = f.snippet ?? file.lines[line - 1]?.trim();
  const { snippet: _drop, ...rest } = f;
  return {
    ...rest,
    layer: "source",
    status: "code",
    location: `${file.path}:${line}`,
    source: { file: file.path, line, column, snippet: clip(snippet) },
  };
}

function clip(s: string | undefined): string | undefined {
  if (!s) return undefined;
  const trimmed = s.trim();
  return trimmed.length > 200 ? trimmed.slice(0, 197) + "..." : trimmed;
}

/** Keeps only the remediations that apply to the detected stacks, plus the stack-agnostic ones. */
export function forStacks(remediation: Remediation[], stacks: Stack[]): Remediation[] {
  if (stacks.length === 0) return remediation;
  const filtered = remediation.filter((r) => r.stack === "any" || stacks.includes(r.stack));
  return filtered.length > 0 ? filtered : remediation;
}

export type { SourceFile, SourceLocation };
