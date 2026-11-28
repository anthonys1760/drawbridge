export interface ViewHit {
  rule: string;
  path: string;
  span: [number, number];
}

export interface ArgPiece {
  text: string;
  hit?: { rule: string; path: string; noteId: string };
}

export interface ChainEvent {
  tool?: string;
  method?: string;
  upstream?: string;
  taint?: { tainted: boolean; sources: string[] };
  taintAfter?: { tainted: boolean; sources: string[] };
  scanner?: { verdict?: string; hits?: { rule: string }[] };
}

/** Keep the current selection. When nothing is selected, open the first pending call. */
export function defaultSelection(
  selected: string | null,
  pendingIds: readonly string[],
  keepIds: readonly string[],
): string | null {
  if (selected && (pendingIds.includes(selected) || keepIds.includes(selected))) return selected;
  return pendingIds[0] ?? null;
}

/** Scanner step is the hit that tainted the session, not the pending call's own exfil verdict. */
export function chainSteps(current: ChainEvent, recent: readonly ChainEvent[]): string[] {
  const sources = current.taint?.sources ?? [];
  const introducers = recent.filter(
    (event) => event.taintAfter?.tainted && event.upstream !== undefined && sources.includes(event.upstream),
  );
  const reads = introducers.map((event) => event.tool ?? event.upstream).filter((name): name is string => Boolean(name));
  const rules = [...new Set(introducers.flatMap((event) => event.scanner?.hits?.map((hit) => hit.rule) ?? []))];
  return [
    `Untrusted read · ${reads.join(", ") || sources.join(", ") || "session"}`,
    `Scanner · ${rules.length > 0 ? rules.join(", ") : "–"}`,
    "Session tainted",
    `This call · ${current.tool ?? current.method ?? "call"}`,
  ];
}

export function renderArgs(value: unknown, hits: readonly ViewHit[]): ArgPiece[] {
  return renderValue(value, hits, "", 0);
}

export function hitNote(hit: { rule: string; path: string }): string {
  if (hit.rule === "exfil.untrusted-url") return `Scanner hit ${hit.rule}: this URL appeared in untrusted content.`;
  if (hit.rule === "exfil.untrusted-data" && (hit.path === "to" || hit.path.endsWith(".to"))) {
    return `Scanner hit ${hit.rule}: recipient repeats untrusted data.`;
  }
  if (hit.rule === "exfil.untrusted-data") return `Scanner hit ${hit.rule}: this value repeats untrusted data.`;
  return `Scanner hit ${hit.rule}: ${hit.path}`;
}

export function noteId(hit: ViewHit): string {
  return `hit-${hit.path}-${hit.span[0]}-${hit.span[1]}-${hit.rule}`.replace(/[^a-z0-9_-]/gi, "-");
}

/** New timeout records, in log order. The caller clears the live region before speaking one. */
export function timeoutAnnouncements(
  events: readonly { id: string; decision?: string; tool?: string }[],
  seen: ReadonlySet<string>,
): string[] {
  return events
    .filter((event) => event.decision === "timeout" && !seen.has(event.id))
    .map((event) => `${event.tool ?? "call"} timed out and was denied.`);
}

export function countdownLabel(seconds: number): string {
  const left = Math.max(0, Math.ceil(seconds));
  const minutes = Math.floor(left / 60);
  const rest = left % 60;
  return `${minutes}:${rest.toString().padStart(2, "0")}`;
}

function renderValue(value: unknown, hits: readonly ViewHit[], path: string, indent: number): ArgPiece[] {
  if (typeof value === "string") return renderString(value, hits, path);
  if (typeof value === "number" || typeof value === "boolean" || value === null) return [{ text: JSON.stringify(value) }];
  if (Array.isArray(value)) {
    if (value.length === 0) return [{ text: "[]" }];
    const pieces: ArgPiece[] = [{ text: "[\n" }];
    value.forEach((item, index) => {
      pieces.push({ text: "  ".repeat(indent + 1) });
      pieces.push(...renderValue(item, hits, path ? `${path}[${index}]` : `[${index}]`, indent + 1));
      if (index < value.length - 1) pieces.push({ text: "," });
      pieces.push({ text: "\n" });
    });
    pieces.push({ text: `${"  ".repeat(indent)}]` });
    return pieces;
  }
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length === 0) return [{ text: "{}" }];
    const pieces: ArgPiece[] = [{ text: "{\n" }];
    entries.forEach(([key, child], index) => {
      const next = path ? `${path}.${key}` : key;
      pieces.push({ text: `${"  ".repeat(indent + 1)}${JSON.stringify(key)}: ` });
      pieces.push(...renderValue(child, hits, next, indent + 1));
      if (index < entries.length - 1) pieces.push({ text: "," });
      pieces.push({ text: "\n" });
    });
    pieces.push({ text: `${"  ".repeat(indent)}}` });
    return pieces;
  }
  return [{ text: "null" }];
}

function renderString(value: string, hits: readonly ViewHit[], path: string): ArgPiece[] {
  const mine = hits
    .filter((hit) => hit.path === path && hit.span[0] >= 0 && hit.span[1] > hit.span[0] && hit.span[1] <= value.length)
    .sort((left, right) => left.span[0] - right.span[0]);
  const pieces: ArgPiece[] = [{ text: '"' }];
  let cursor = 0;
  for (const hit of mine) {
    if (hit.span[0] < cursor) continue;
    if (hit.span[0] > cursor) pieces.push({ text: escapeJson(value.slice(cursor, hit.span[0])) });
    pieces.push({
      text: escapeJson(value.slice(hit.span[0], hit.span[1])),
      hit: { rule: hit.rule, path: hit.path, noteId: noteId(hit) },
    });
    cursor = hit.span[1];
  }
  if (cursor < value.length) pieces.push({ text: escapeJson(value.slice(cursor)) });
  pieces.push({ text: '"' });
  return pieces;
}

function escapeJson(text: string): string {
  return JSON.stringify(text).slice(1, -1);
}
