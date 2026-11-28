import type { AuditScanner, AuditScannerHit, ScannerHitTarget } from "./audit.js";

/** Pinned wrap syntax. `<<untrusted>>` is 13 UTF-16 units; with the trailing LF the prefix is 14. */
export const WRAP_PREFIX = "<<untrusted>>\n";
/** Pinned wrap syntax. `<<end untrusted>>` is 17 UTF-16 units; with the leading LF the suffix is 18. */
export const WRAP_SUFFIX = "\n<<end untrusted>>";
export const BLOCKED_RESULT_TEXT = "Blocked by Drawbridge. The tool result was withheld.";
export const BLOCKED_DESCRIPTION = "Blocked by Drawbridge. The tool description was withheld.";

/**
 * Case-insensitive phrases. A hit is the matched slice, not a score.
 * Patterns are anchored to the phrase so nearby benign words do not match.
 */
export const HEURISTICS: { rule: string; pattern: RegExp }[] = [
  {
    rule: "instruction-override",
    pattern: /ignore (?:all |any )?(?:previous|prior|above) (?:instructions|prompts|rules)/i,
  },
  {
    rule: "instruction-override",
    pattern: /disregard (?:all |any )?(?:previous|prior|above) (?:instructions|prompts|rules)/i,
  },
  { rule: "system-prompt", pattern: /system prompt/i },
  { rule: "role-hijack", pattern: /\byou are now\b/i },
  { rule: "role-hijack", pattern: /\bdo not tell the user\b/i },
  { rule: "exfiltrate", pattern: /\bexfiltrat(?:e|ion)\b/i },
  { rule: "hidden-role", pattern: /<\|im_start\|>/i },
];

export interface ScannerAllowEntry {
  match: string;
  upstream: string;
  expires: string;
}

export interface ScannerOptions {
  mode: "block" | "warn" | "wrap";
  scanDescriptions: boolean;
  allowlist: ScannerAllowEntry[];
  now?: number;
}

interface LocatedHit {
  rule: string;
  span: [number, number];
  target: ScannerHitTarget;
  path: string;
  /** The string the span indexes before wrapping or withholding. */
  text: string;
}

export interface ScanOutcome {
  result: unknown;
  scanner?: AuditScanner;
}

const IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/;

export function scanText(text: string): { rule: string; span: [number, number] }[] {
  const hits: { rule: string; span: [number, number] }[] = [];
  for (const heuristic of HEURISTICS) {
    const flags = heuristic.pattern.flags.includes("g") ? heuristic.pattern.flags : `${heuristic.pattern.flags}g`;
    const expression = new RegExp(heuristic.pattern.source, flags);
    for (const match of text.matchAll(expression)) {
      if (match.index === undefined || match[0].length === 0) continue;
      hits.push({ rule: heuristic.rule, span: [match.index, match.index + match[0].length] });
    }
  }
  hits.sort((left, right) => left.span[0] - right.span[0] || left.span[1] - right.span[1]);
  return hits;
}

/**
 * Scan a tool result or a `{ tools }` catalog. Description fields are skipped
 * when `scanDescriptions` is false. In wrap mode the returned strings are the
 * wrapped text and spans index that text. In block mode the payload is replaced
 * and spans still index the withheld text.
 */
export function applyScanner(value: unknown, upstream: string, options: ScannerOptions): ScanOutcome {
  const located = collect(value, "", upstream, options);
  if (located.length === 0) return { result: value };
  const mode = options.mode;
  if (mode === "warn") {
    return { result: value, scanner: { verdict: "flagged", hits: toHits(located) } };
  }
  if (mode === "wrap") {
    const wrapped = wrapValue(value, located);
    return { result: wrapped, scanner: { verdict: "wrapped", hits: toHits(shiftWrapped(located)) } };
  }
  return {
    result: blockedReplacement(value, located),
    scanner: { verdict: "blocked", hits: toHits(located) },
  };
}

export function blockedToolResult(): { isError: true; content: [{ type: "text"; text: string }] } {
  return { isError: true, content: [{ type: "text", text: BLOCKED_RESULT_TEXT }] };
}

function toHits(located: LocatedHit[]): AuditScannerHit[] {
  return located.map((hit) => ({
    rule: hit.rule,
    span: hit.span,
    target: hit.target,
    path: hit.path,
  }));
}

function shiftWrapped(located: LocatedHit[]): LocatedHit[] {
  return located.map((hit) => ({
    ...hit,
    span: [hit.span[0] + WRAP_PREFIX.length, hit.span[1] + WRAP_PREFIX.length],
  }));
}

function collect(value: unknown, path: string, upstream: string, options: ScannerOptions): LocatedHit[] {
  if (typeof value === "string") {
    if (!path) return [];
    const target = targetFor(path);
    if (target === "description" && !options.scanDescriptions) return [];
    return scanText(value)
      .filter((hit) => !suppressed(value, hit.span, upstream, options))
      .map((hit) => ({ ...hit, target, path, text: value }));
  }
  if (Array.isArray(value)) {
    return value.flatMap((item, index) => {
      if (!path) return [];
      return collect(item, `${path}[${index}]`, upstream, options);
    });
  }
  if (value !== null && typeof value === "object") {
    return Object.entries(value).flatMap(([key, child]) => {
      if (!IDENT.test(key)) return [];
      const next = path ? `${path}.${key}` : key;
      return collect(child, next, upstream, options);
    });
  }
  return [];
}

function targetFor(path: string): ScannerHitTarget {
  return path === "description" || path.endsWith(".description") ? "description" : "result";
}

function suppressed(text: string, span: [number, number], upstream: string, options: ScannerOptions): boolean {
  const now = options.now ?? Date.now();
  for (const entry of options.allowlist) {
    if (entry.upstream !== upstream) continue;
    const expires = Date.parse(entry.expires);
    if (Number.isNaN(expires) || expires <= now) continue;
    let from = 0;
    while (from < text.length) {
      const at = text.indexOf(entry.match, from);
      if (at < 0) break;
      const end = at + entry.match.length;
      if (span[0] >= at && span[1] <= end) return true;
      from = at + 1;
    }
  }
  return false;
}

function wrapValue(value: unknown, hits: LocatedHit[]): unknown {
  const paths = new Set(hits.map((hit) => hit.path));
  return mapStrings(value, "", (text, path) => (paths.has(path) ? `${WRAP_PREFIX}${text}${WRAP_SUFFIX}` : text));
}

function mapStrings(value: unknown, path: string, visit: (text: string, path: string) => string): unknown {
  if (typeof value === "string") return path ? visit(value, path) : value;
  if (Array.isArray(value)) {
    return value.map((item, index) => mapStrings(item, path ? `${path}[${index}]` : "", visit));
  }
  if (value !== null && typeof value === "object") {
    const output: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value)) {
      const next = IDENT.test(key) ? (path ? `${path}.${key}` : key) : "";
      output[key] = mapStrings(child, next, visit);
    }
    return output;
  }
  return value;
}

function blockedReplacement(value: unknown, hits: LocatedHit[]): unknown {
  if (isToolCatalog(value)) {
    const blocked = new Set(hits.map((hit) => hit.path));
    return mapStrings(value, "", (text, path) => {
      if (!blocked.has(path)) return text;
      return path.endsWith("description") ? BLOCKED_DESCRIPTION : BLOCKED_RESULT_TEXT;
    });
  }
  return blockedToolResult();
}

function isToolCatalog(value: unknown): value is { tools: Record<string, unknown>[] } {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const tools = (value as { tools?: unknown }).tools;
  return Array.isArray(tools);
}
