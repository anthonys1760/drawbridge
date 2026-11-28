import type { AuditScanner, AuditScannerHit } from "./audit.js";
import { maskEmail } from "./redact.js";

/** Outbound tools the send-after-taint flow holds. A tainted session flags derived args. */
export const OUTBOUND_TOOL_GLOBS = ["*__send", "*__http_post", "*__create_issue"] as const;

const URL_PATTERN = /https?:\/\/[^\s"'<>]+/gi;
const TOKEN_PATTERN = /[A-Za-z0-9][A-Za-z0-9._:@/-]{11,}/g;
const IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/;

export function isOutboundTool(tool: string): boolean {
  return OUTBOUND_TOOL_GLOBS.some((pattern) => globMatches(pattern, tool));
}

function globMatches(glob: string, name: string): boolean {
  let pattern = "^";
  for (const char of glob) {
    if (char === "*") pattern += ".*";
    else if (char === "?") pattern += ".";
    else pattern += /[\\^$+?.()|[\]{}]/.test(char) ? `\\${char}` : char;
  }
  return new RegExp(`${pattern}$`).test(name);
}

/** Pull string leaves out of a tool result so later outbound args can be compared. */
export function collectText(value: unknown, out: string[] = []): string[] {
  if (typeof value === "string") {
    if (value.length > 0) out.push(value.slice(0, 2000));
    return out;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectText(item, out);
    return out;
  }
  if (value !== null && typeof value === "object") {
    for (const child of Object.values(value)) collectText(child, out);
  }
  return out;
}

/**
 * Hits for outbound arguments that carry a URL or a long token seen in
 * untrusted tool output. Spans index `argsRedacted`, not the raw arguments.
 * Returns undefined when nothing matches. This is not a detection-rate score.
 */
export function exfilScanner(raw: unknown, redacted: unknown, corpus: readonly string[]): AuditScanner | undefined {
  if (corpus.length === 0) return undefined;
  const hits: AuditScannerHit[] = [];
  walk(raw, redacted, "", corpus, hits);
  if (hits.length === 0) return undefined;
  return { verdict: "flagged", hits: hits.slice(0, 8) };
}

function walk(
  raw: unknown,
  redacted: unknown,
  path: string,
  corpus: readonly string[],
  hits: AuditScannerHit[],
): void {
  if (typeof raw === "string" && typeof redacted === "string" && path) {
    for (const hit of hitsInString(raw, redacted, path, corpus)) {
      if (hits.length >= 8) return;
      hits.push(hit);
    }
    return;
  }
  if (Array.isArray(raw) && Array.isArray(redacted)) {
    const count = Math.min(raw.length, redacted.length);
    for (let index = 0; index < count; index += 1) {
      walk(raw[index], redacted[index], path ? `${path}[${index}]` : "", corpus, hits);
    }
    return;
  }
  if (raw !== null && typeof raw === "object" && redacted !== null && typeof redacted === "object" && !Array.isArray(raw)) {
    const redactedRecord = redacted as Record<string, unknown>;
    for (const [key, child] of Object.entries(raw as Record<string, unknown>)) {
      if (!IDENT.test(key) || !Object.hasOwn(redactedRecord, key)) continue;
      const next = path ? `${path}.${key}` : key;
      walk(child, redactedRecord[key], next, corpus, hits);
    }
  }
}

function hitsInString(raw: string, redacted: string, path: string, corpus: readonly string[]): AuditScannerHit[] {
  const hits: AuditScannerHit[] = [];
  const seen = new Set<string>();
  const push = (rule: string, needle: string) => {
    if (hits.length >= 4 || seen.has(`${rule}:${needle}`)) return;
    const span = locate(redacted, needle);
    if (!span) return;
    seen.add(`${rule}:${needle}`);
    hits.push({ rule, span, target: "args", path });
  };

  if (raw.length >= 12 && corpus.some((text) => text.includes(raw))) {
    push("exfil.untrusted-data", displayNeedle(raw, redacted));
  }

  const urls = [...raw.matchAll(new RegExp(URL_PATTERN.source, "gi"))].map((match) => match[0]).filter(Boolean);
  for (const url of urls) {
    if (corpus.some((text) => text.includes(url))) push("exfil.untrusted-url", url);
  }

  for (const text of corpus) {
    for (const match of text.matchAll(new RegExp(TOKEN_PATTERN.source, "g"))) {
      const token = match[0];
      if (!token || token.length < 12 || !raw.includes(token)) continue;
      if (urls.some((url) => url.includes(token))) continue;
      push("exfil.untrusted-data", displayNeedle(token, redacted));
    }
  }
  return hits;
}

function displayNeedle(rawNeedle: string, redacted: string): string {
  if (redacted.includes(rawNeedle)) return rawNeedle;
  if (rawNeedle.includes("@")) {
    const masked = maskEmail(rawNeedle);
    if (redacted.includes(masked)) return masked;
  }
  return rawNeedle;
}

function locate(text: string, needle: string): [number, number] | undefined {
  const start = text.indexOf(needle);
  if (start < 0) return undefined;
  return [start, start + needle.length];
}
