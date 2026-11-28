import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { color, scale, type } from "../../../docs/design/tokens.ts";

describe("design tokens", () => {
  it("keeps the dark mint accent in the CSS the dashboard imports", () => {
    const css = readFileSync(new URL("../../../docs/design/tokens.css", import.meta.url), "utf8");
    expect(css).toContain("--db-bg: #0B0D10");
    expect(css).toContain("--db-text-subtle: #808996");
    expect(css).toContain("--db-focus: #86B0FF");
    expect(css).toContain("--db-text-faint: var(--db-text-subtle)");
    expect(css).toContain("@media (prefers-color-scheme: light)");
    expect(css).not.toContain("box-shadow");
    expect(css.toLowerCase()).toContain("--db-accent: #5ee6a8");
    expect(color.accent).toBe("var(--db-accent)");
    expect(type["3xl"]).toBe("var(--db-text-3xl)");
    expect(scale.topbarH).toBe("var(--db-topbar-h)");
  });
});
