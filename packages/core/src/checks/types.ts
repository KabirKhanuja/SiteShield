import type { Response } from "undici";
import type { Finding, Layer } from "../types.ts";

export type CheckContext = {
  /** Site origin being scanned, already validated. */
  url: URL;
  /** The homepage response, fetched once and shared by the checks that only need headers. */
  home: { response: Response; finalUrl: URL };
  signal?: AbortSignal;
};

export type Check = {
  id: string;
  layer: Layer;
  /** active checks send test traffic and only run on verified domains. */
  mode: "passive" | "active";
  run(ctx: CheckContext): Promise<Finding[]>;
};

/** Small helper so each check only spells out what is specific to it. */
export function liveFinding(f: Omit<Finding, "layer" | "status">): Finding {
  return { ...f, layer: "live", status: "live" };
}
