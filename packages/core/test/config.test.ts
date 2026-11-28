import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ConfigError, loadConfig, redact } from "../src/index.js";

const BASE = `
version: 1
audit:
  path: ./audit.jsonl
upstreams:
  notes:
    transport: stdio
    command: ["node", "server.js"]
`;

describe("loadConfig", () => {
  it("loads the checked-in example", async () => {
    const root = join(dirname(fileURLToPath(import.meta.url)), "../../..");
    const config = loadConfig(await readFile(join(root, "examples/drawbridge.yaml"), "utf8"));
    expect(config.upstreams.map((entry) => entry.name)).toEqual(["notes"]);
    expect(config.upstreams[0]?.upstream.transport).toBe("stdio");
  });

  it("loads a stdio upstream and interpolates env vars", () => {
    const config = loadConfig(
      `
version: 1
audit:
  path: \${AUDIT_DIR}/audit.jsonl
upstreams:
  remote:
    transport: http
    url: http://127.0.0.1:\${PORT}/mcp
    headers:
      Authorization: Bearer \${TOKEN}
`,
      { AUDIT_DIR: "/tmp/db", PORT: "9", TOKEN: "sekret" },
    );
    expect(config.audit.path).toBe("/tmp/db/audit.jsonl");
    expect(config.upstreams[0]?.name).toBe("remote");
    const upstream = config.upstreams[0]?.upstream;
    expect(upstream?.transport).toBe("http");
    if (upstream?.transport === "http") {
      expect(upstream.url).toBe("http://127.0.0.1:9/mcp");
      expect(upstream.headers?.Authorization).toBe("Bearer sekret");
    }
  });

  it("refuses policy sections, tool pinning, and secretRef", () => {
    expect(() => loadConfig(`${BASE}rules:\n  - tool: notes__read\n    action: allow\n`)).toThrow(ConfigError);
    expect(() =>
      loadConfig(`
version: 1
upstreams:
  notes:
    transport: stdio
    command: ["node", "server.js"]
    pinTools: true
`),
    ).toThrow(/pinTools/);
    expect(() =>
      loadConfig(`
version: 1
upstreams:
  notes:
    transport: stdio
    command: ["node", "server.js"]
    auth:
      secretRef: keychain:mail-token
`),
    ).toThrow(/secretRef/);
  });

  it("rejects an empty upstream map and a missing env var", () => {
    expect(() => loadConfig("version: 1\nupstreams: {}\n")).toThrow(/at least one upstream/);
    expect(() =>
      loadConfig(
        `
version: 1
upstreams:
  notes:
    transport: stdio
    command: ["\${MISSING}", "server.js"]
`,
        {},
      ),
    ).toThrow(/MISSING/);
  });
});

describe("redact", () => {
  it("masks secret-shaped keys and leaves ordinary arguments", () => {
    expect(redact({ message: "hi", token: "super-secret", nested: { apiKey: "k" } })).toEqual({
      message: "hi",
      token: "[REDACTED]",
      nested: { apiKey: "[REDACTED]" },
    });
    expect(redact("mail me at ada@example.com")).toBe("mail me at [REDACTED_EMAIL]");
  });
});
