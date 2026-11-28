import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { color } from "../../../docs/design/tokens.ts";

describe("design tokens", () => {
  it("keeps the dark mint accent in the CSS the dashboard imports", () => {
    const css = readFileSync(new URL("../../../docs/design/tokens.css", import.meta.url), "utf8");
    expect(css).toContain(`--db-accent: ${color.dark.accent}`);
    expect(css).toContain(`--db-warn: ${color.dark.warn}`);
    expect(css).toContain(`--db-danger: ${color.dark.danger}`);
    expect(color.dark.accent).toBe("#5EE6A8");
  });
});
