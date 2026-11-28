import { access } from "node:fs/promises";
import { namespaceTool, savePinFile, toolDefinitionHash, type DrawbridgeConfig } from "@drawbridge/core";
import { openUpstreamPool } from "./upstreams.js";

/**
 * Write the current upstream tool-definition hashes.
 * `update` replaces an existing file. The first `pin` refuses to overwrite.
 */
export async function pinUpstreams(config: DrawbridgeConfig, pinPath: string, update: boolean): Promise<number> {
  if (!update) {
    const exists = await access(pinPath).then(
      () => true,
      () => false,
    );
    if (exists) {
      throw new Error(`Pin file ${pinPath} already exists. Run \`drawbridge pin update --config <file>\` to replace it.`);
    }
  }
  const { pool } = await openUpstreamPool(config);
  try {
    const tools: Record<string, string> = {};
    for (const entry of config.upstreams) {
      const listed = await pool.listTools(entry.name);
      for (const tool of listed) {
        tools[namespaceTool(entry.name, tool.name)] = toolDefinitionHash(tool);
      }
    }
    await savePinFile(pinPath, { version: 1, tools });
    return Object.keys(tools).length;
  } finally {
    await pool.close();
  }
}
