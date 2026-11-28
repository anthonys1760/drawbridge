import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { loadConfig, redact } from "../src/index.js";

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
    expect(config.upstreams.map((entry) => entry.name)).toEqual(["mail", "notes"]);
    expect(config.upstreams[0]?.upstream.transport).toBe("stdio");
    expect(config.upstreams[1]?.upstream.transport).toBe("stdio");
    expect(config.scanner.mode).toBe("wrap");
    expect(config.defaults.action).toBe("deny");
    const send = config.rules.find((rule) => rule.tool === "mail__send");
    expect(send?.action).toBe("allow");
    expect(send?.args).toBeUndefined();
    expect(config.flows[0]?.name).toBe("no-send-after-untrusted-content");
    expect(config.flows[0]?.action).toBe("approve");
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

  it("accepts policy sections and tool pinning, and still refuses secretRef", () => {
    const config = loadConfig(`${BASE}rules:\n  - tool: notes__read\n    action: allow\n`);
    expect(config.rules).toHaveLength(1);
    const pinned = loadConfig(`
version: 1
upstreams:
  notes:
    transport: stdio
    command: ["node", "server.js"]
    pinTools: true
`);
    expect(pinned.upstreams[0]?.upstream.pinTools).toBe(true);
    expect(pinned.upstreams[0]?.upstream.onPinMismatch).toBe("deny");
    expect(() =>
      loadConfig(`
version: 1
rules:
  - tool: notes__read
    action: allow
    args:
      path:
        pattern: "("
upstreams:
  notes:
    transport: stdio
    command: ["node", "server.js"]
`),
    ).toThrow(/pattern/);
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
    const referenced = loadConfig(
      `
version: 1
upstreams:
  notes:
    transport: stdio
    command: ["node", "server.js"]
    secrets:
      NOTES_TOKEN: env:NOTES_TOKEN
  remote:
    transport: http
    url: http://127.0.0.1:9/mcp
    secrets:
      Authorization: file:/tmp/remote-token
`,
      {},
    );
    const notes = referenced.upstreams.find((entry) => entry.name === "notes")?.upstream;
    const remote = referenced.upstreams.find((entry) => entry.name === "remote")?.upstream;
    expect(notes?.secrets).toEqual({ NOTES_TOKEN: "env:NOTES_TOKEN" });
    expect(remote?.secrets).toEqual({ Authorization: "file:/tmp/remote-token" });
    expect(JSON.stringify(referenced)).not.toContain("literal-secret");
    let refused = "";
    try {
      loadConfig(`
version: 1
upstreams:
  notes:
    transport: stdio
    command: ["node", "server.js"]
    secrets:
      TOKEN: literal-secret-value-should-not-appear
`);
    } catch (error) {
      refused = error instanceof Error ? error.message : String(error);
    }
    expect(refused).toMatch(/env:NAME or file:PATH/);
    expect(refused).not.toContain("literal-secret-value-should-not-appear");
    expect(() =>
      loadConfig(`
version: 1
scanner:
  classifier: api
upstreams:
  notes:
    transport: stdio
    command: ["node", "server.js"]
`),
    ).toThrow(/classifier/);
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
    expect(redact("mail me at ada@example.com")).toBe("mail me at a•••@example.com");
    expect(redact("john@outsidecorp.com")).toBe("j•••@outsidecorp.com");
    expect(redact("q@outside-sample.example")).toBe("q•••@outside-sample.example");
    expect(redact({ to: "q@outside-sample.example", token: "q@outside-sample.example" })).toEqual({
      to: "q•••@outside-sample.example",
      token: "[REDACTED]",
    });
    expect(redact("Bearer sekret and sk-abcdefgh")).toBe("Bearer [REDACTED] and [REDACTED]");
  });
});
