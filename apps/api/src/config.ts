import { z } from "zod";

const schema = z.object({
  PORT: z.coerce.number().int().min(1).max(65535).default(4000),
  HOST: z.string().default("127.0.0.1"),
  WEB_ORIGINS: z
    .string()
    .default("http://localhost:3000")
    .transform((v) => v.split(",").map((s) => s.trim()).filter(Boolean)),
  DATABASE_PATH: z.string().default("./data/siteshield.db"),
  SCAN_CONCURRENCY: z.coerce.number().int().min(1).max(10).default(2),
  TRUST_PROXY: z.coerce.number().int().min(0).max(5).default(0),
  SCANS_PER_10_MIN: z.coerce.number().int().min(1).default(10),
});

export type Config = z.infer<typeof schema>;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  return schema.parse(env);
}
