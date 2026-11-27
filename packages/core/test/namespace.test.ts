import { describe, expect, it } from "vitest";
import { namespaceTool, parseNamespacedTool } from "../src/index.js";

describe("tool names", () => {
  const upstreams = new Set(["notes", "remote"]);

  it("round-trips a tool whose own name contains the separator", () => {
    const advertised = namespaceTool("notes", "a__b");
    expect(advertised).toBe("notes__a__b");
    expect(parseNamespacedTool(advertised, upstreams)).toEqual({ upstream: "notes", tool: "a__b" });
  });

  it("rejects names that do not select a known upstream", () => {
    expect(parseNamespacedTool("read", upstreams)).toBeUndefined();
    expect(parseNamespacedTool("mail__send", upstreams)).toBeUndefined();
    expect(parseNamespacedTool("__read", upstreams)).toBeUndefined();
  });
});
