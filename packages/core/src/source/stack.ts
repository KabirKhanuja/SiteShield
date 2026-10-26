import type { Stack } from "../types.ts";
import type { PackageJson, SourceFile } from "./types.ts";

/**
 * Works out which frameworks a project uses, so remediation shows the right snippet and
 * the auth and CORS checks know what a route looks like. A project can be more than one,
 * for example a Next.js app deployed on Vercel.
 */
export function detectStacks(files: SourceFile[], packages: PackageJson[]): Stack[] {
  const stacks = new Set<Stack>();
  const deps = new Map<string, string>();
  for (const pkg of packages) {
    for (const [name, version] of Object.entries({ ...pkg.data.dependencies, ...pkg.data.devDependencies })) {
      deps.set(name, version);
    }
  }

  if (deps.has("next")) stacks.add("nextjs");
  if (deps.has("express")) stacks.add("express");

  const names = new Set(files.map((f) => f.path.toLowerCase()));
  const hasFile = (suffix: string) => [...names].some((n) => n === suffix || n.endsWith("/" + suffix));

  if (hasFile("next.config.js") || hasFile("next.config.ts") || hasFile("next.config.mjs")) stacks.add("nextjs");
  if (hasFile("vercel.json") || files.some((f) => f.path.startsWith(".vercel/"))) stacks.add("vercel");
  if (hasFile("nginx.conf") || [...names].some((n) => n.includes("nginx"))) stacks.add("nginx");

  return [...stacks];
}
