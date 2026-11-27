import { createHash } from "node:crypto";

/** sha256 hex digest. */
export function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

/**
 * Canonical JSON for audit hashes. No whitespace.
 * Object keys are sorted by UTF-16 code unit (`Array#sort` on the keys).
 * `undefined` object entries are dropped. `undefined` array entries become
 * null. Strings, numbers, booleans, and null use `JSON.stringify`.
 */
export function stableStringify(value: unknown): string {
  if (value === undefined) return "null";
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value) ?? "null";
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record)
    .filter((key) => record[key] !== undefined)
    .sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableStringify(record[key])}`).join(",")}}`;
}
