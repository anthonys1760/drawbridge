import { readFile, writeFile } from "node:fs/promises";
import { z } from "zod";
import { ConfigError } from "./errors.js";
import { sha256, stableStringify } from "./hash.js";

/**
 * Fields that identify a tool definition for rug-pull detection.
 * The hash is sha256 of the canonical JSON of this object. Undefined
 * fields are omitted, and object keys are sorted, so two listings of the
 * same definition produce the same hash.
 */
export interface ToolDefinition {
  name: string;
  description?: string;
  title?: string;
  inputSchema: unknown;
  outputSchema?: unknown;
  annotations?: unknown;
}

export function toolDefinitionHash(tool: ToolDefinition): string {
  return sha256(
    stableStringify({
      name: tool.name,
      ...(tool.title !== undefined ? { title: tool.title } : {}),
      ...(tool.description !== undefined ? { description: tool.description } : {}),
      inputSchema: tool.inputSchema,
      ...(tool.outputSchema !== undefined ? { outputSchema: tool.outputSchema } : {}),
      ...(tool.annotations !== undefined ? { annotations: tool.annotations } : {}),
    }),
  );
}

const pinFileSchema = z.strictObject({
  version: z.literal(1),
  tools: z.record(z.string(), z.string().regex(/^[a-f0-9]{64}$/)),
});

export type PinFile = z.infer<typeof pinFileSchema>;

export async function loadPinFile(path: string): Promise<PinFile> {
  const text = await readFile(path, "utf8").catch((error: NodeJS.ErrnoException) => {
    if (error.code === "ENOENT") {
      throw new ConfigError(
        `Pin file ${path} does not exist. Run \`drawbridge pin --config <file>\` before starting with pinTools enabled.`,
      );
    }
    throw new ConfigError(`Cannot read pin file ${path}: ${error.message}`);
  });
  let raw: unknown;
  try {
    raw = JSON.parse(text) as unknown;
  } catch (error) {
    throw new ConfigError(`Pin file ${path} is not valid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  const parsed = pinFileSchema.safeParse(raw);
  if (!parsed.success) {
    throw new ConfigError(`Pin file ${path} is invalid: ${parsed.error.issues.map((issue) => issue.message).join("; ")}`);
  }
  return parsed.data;
}

export async function savePinFile(path: string, pins: PinFile): Promise<void> {
  const parsed = pinFileSchema.parse(pins);
  await writeFile(path, `${JSON.stringify(parsed, null, 2)}\n`, "utf8");
}
