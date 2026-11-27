import { CLIENT_INFO_META_KEY } from "@modelcontextprotocol/server";
import type { PolicyClient } from "@drawbridge/core";

export interface RequestContext {
  mcpReq?: {
    envelope?: object;
  };
}

/** Client identity from the 2026-07-28 per-request `_meta` envelope. */
export function readClientInfo(ctx: RequestContext | undefined): PolicyClient {
  const envelope = ctx?.mcpReq?.envelope as Record<string, unknown> | undefined;
  const info = envelope?.[CLIENT_INFO_META_KEY];
  if (info === null || typeof info !== "object") return {};
  const record = info as Record<string, unknown>;
  const name = typeof record.name === "string" ? record.name : undefined;
  const version = typeof record.version === "string" ? record.version : undefined;
  return {
    ...(name !== undefined ? { name } : {}),
    ...(version !== undefined ? { version } : {}),
  };
}
