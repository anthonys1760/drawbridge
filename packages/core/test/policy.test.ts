import { describe, expect, it } from "vitest";
import { loadConfig, toolDefinitionHash, YamlPolicy, type DrawbridgeConfig, type PreCallInput } from "../src/index.js";

const NOTES = `
version: 1
upstreams:
  notes:
    transport: stdio
    command: ["node", "server.js"]
    trusted: false
  mail:
    transport: stdio
    command: ["node", "mail.js"]
    trusted: true
`;

function config(extra = ""): DrawbridgeConfig {
  return loadConfig(`${extra}\n${NOTES}`);
}

function call(policy: YamlPolicy, tool: string, extra: Partial<PreCallInput> = {}) {
  const upstream = tool.split("__")[0] ?? "notes";
  return policy.preCall({
    sessionId: "s",
    method: "tools/call",
    upstream,
    tool,
    args: {},
    client: { name: "t" },
    trusted: upstream === "mail",
    catalog: "ready",
    ...extra,
  });
}

describe("YamlPolicy", () => {
  it("lets the first matching rule win and denies the rest", async () => {
    const policy = new YamlPolicy(
      config(`
rules:
  - tool: notes__*
    action: allow
  - tool: notes__read
    action: deny
`),
    );
    expect((await call(policy, "notes__read")).ruleId).toBe("rule:0");
    expect((await call(policy, "notes__read")).decision).toBe("allow");
    const exact = new YamlPolicy(
      config(`
rules:
  - tool: notes__read
    action: allow
`),
    );
    expect((await call(exact, "notes__reader")).decision).toBe("deny");
    expect((await call(exact, "notes__reader")).ruleId).toBe("default:deny");

    const starred = new YamlPolicy(
      config(`
rules:
  - tool: "*__delete_*"
    action: deny
  - tool: mail__*
    action: allow
`),
    );
    expect((await call(starred, "mail__delete_file")).ruleId).toBe("rule:0");
    expect((await call(starred, "mail__send")).decision).toBe("allow");
  });

  it("checks arguments on allow and skips them on deny", async () => {
    const policy = new YamlPolicy(
      config(`
rules:
  - tool: notes__read
    action: allow
    args:
      path:
        pattern: "^notes/.*\\\\.md$"
        maxLength: 12
  - tool: mail__send
    action: allow
    args:
      to:
        allowDomains: ["outsidecorp.com"]
  - tool: mail__pick
    action: allow
    args:
      choice:
        enum: ["a", "b"]
  - tool: notes__echo
    action: deny
    args:
      message:
        pattern: "^ok$"
`),
    );
    expect((await call(policy, "notes__read", { args: { path: "notes/a.md" } })).decision).toBe("allow");
    const outside = await call(policy, "notes__read", { args: { path: "/etc/passwd" } });
    expect(outside.decision).toBe("deny");
    expect(outside.reason).toMatch(/does not match/);
    expect((await call(policy, "notes__read", { args: { path: "notes/too-long.md" } })).reason).toMatch(/maxLength/);
    expect((await call(policy, "notes__read", { args: {} })).reason).toMatch(/required/);
    expect((await call(policy, "notes__read", { args: { path: 1 } })).reason).toMatch(/string/);

    expect((await call(policy, "mail__send", { args: { to: "A@Outsidecorp.com" } })).decision).toBe("allow");
    expect((await call(policy, "mail__send", { args: { to: "a@sub.outsidecorp.com" } })).reason).toMatch(/domain/);
    expect((await call(policy, "mail__send", { args: { to: "nodomain" } })).reason).toMatch(/domain/);
    expect((await call(policy, "mail__pick", { args: { choice: "a" } })).decision).toBe("allow");
    expect((await call(policy, "mail__pick", { args: { choice: "c" } })).reason).toMatch(/one of/);
    expect(
      (await call(policy, "mail__send", { args: { to: ["a@outsidecorp.com", "b@evil.com"] } })).decision,
    ).toBe("deny");
    expect((await call(policy, "mail__send", { args: { to: [] } })).reason).toMatch(/required/);

    const denied = await call(policy, "notes__echo", { args: { message: "nope" } });
    expect(denied.decision).toBe("deny");
    expect(denied.reason).toMatch(/Matched rule/);
  });

  it("rate limits allow and approve, and a deny does not consume quota", async () => {
    let now = 0;
    const policy = new YamlPolicy(
      config(`
defaults:
  action: deny
  rateLimit:
    perSession: 1
rules:
  - tool: notes__echo
    action: allow
    rateLimit:
      perMinute: 1
`),
      { now: () => now },
    );
    expect((await call(policy, "notes__read")).decision).toBe("deny");
    expect((await call(policy, "notes__echo")).decision).toBe("allow");
    expect((await call(policy, "notes__echo")).ruleId).toBe("rate:notes__echo");
    now = 59_999;
    expect((await call(policy, "notes__echo")).ruleId).toBe("rate:notes__echo");
    now = 60_000;
    expect((await call(policy, "notes__echo")).ruleId).toBe("rate:session");
  });

  it("lets a flow tighten an allow and refuses to loosen a deny", async () => {
    const policy = new YamlPolicy(
      config(`
rules:
  - tool: mail__send
    action: allow
  - tool: mail__drop
    action: deny
flows:
  - name: no-send-after-untrusted-content
    when:
      sessionTainted: true
    tools: [mail__send, mail__drop]
    action: approve
    reason: Untrusted content entered this session
  - name: later-deny
    when:
      sessionTainted: true
    tools: [mail__send]
    action: deny
`),
    );
    expect((await call(policy, "mail__send")).decision).toBe("allow");
    policy.seedTaint({ tainted: true, sources: ["notes"] });
    const held = await call(policy, "mail__send");
    expect(held.decision).toBe("approve");
    expect(held.ruleId).toBe("flow:no-send-after-untrusted-content");
    expect(held.expiresAt).toEqual(expect.any(String));
    expect(held.taint).toEqual({ tainted: true, sources: ["notes"] });
    const dropped = await call(policy, "mail__drop");
    expect(dropped.decision).toBe("deny");
    expect(dropped.ruleId).toBe("rule:1");
  });

  it("uses annotations only for a trusted server when no rule matched", async () => {
    const policy = new YamlPolicy(config("defaults:\n  action: deny\n  fromAnnotations: true\n"));
    const readOnly = await call(policy, "mail__read", {
      trusted: true,
      annotations: { readOnlyHint: true },
    });
    expect(readOnly.ruleId).toBe("annotation:readOnlyHint");
    const destructive = await call(policy, "mail__drop", {
      trusted: true,
      annotations: { readOnlyHint: true, destructiveHint: true },
    });
    expect(destructive.decision).toBe("approve");
    expect(destructive.ruleId).toBe("annotation:destructiveHint");
    const untrusted = await call(policy, "notes__read", {
      trusted: false,
      annotations: { readOnlyHint: true },
    });
    expect(untrusted.ruleId).toBe("default:deny");

    const ignored = new YamlPolicy(config("defaults:\n  action: deny\n  fromAnnotations: false\n"));
    expect(
      (
        await call(ignored, "mail__read", {
          trusted: true,
          annotations: { readOnlyHint: true },
        })
      ).decision,
    ).toBe("deny");

    const ruled = new YamlPolicy(
      config(`
rules:
  - tool: mail__read
    action: deny
`),
    );
    expect(
      (
        await call(ruled, "mail__read", {
          trusted: true,
          annotations: { readOnlyHint: true },
        })
      ).ruleId,
    ).toBe("rule:0");
  });

  it("denies or holds a pin mismatch before rules, and allows a matching pin", async () => {
    const definition = { name: "read", inputSchema: { type: "object" } };
    const hash = toolDefinitionHash(definition);
    const yaml = `
rules:
  - tool: notes__read
    action: allow
upstreams:
  notes:
    transport: stdio
    command: ["node", "server.js"]
    pinTools: true
    onPinMismatch: deny
`;
    const policy = new YamlPolicy(loadConfig(`version: 1\n${yaml}`), {
      pins: { version: 1, tools: { notes__read: hash } },
    });
    expect((await call(policy, "notes__read", { definition, catalog: "ready" })).decision).toBe("allow");
    const changed = await call(policy, "notes__read", {
      definition: { ...definition, description: "changed" },
      catalog: "ready",
    });
    expect(changed.decision).toBe("deny");
    expect(changed.ruleId).toBe("pin:notes__read");
    expect((await call(policy, "notes__read", { catalog: "unavailable", definition })).ruleId).toBe("pin:notes__read");

    const held = new YamlPolicy(
      loadConfig(`version: 1\n${yaml.replace("onPinMismatch: deny", "onPinMismatch: approve")}`),
      { pins: { version: 1, tools: {} } },
    );
    expect((await held.preCall(input("notes__read"))).decision).toBe("approve");

    const listing = new YamlPolicy(config(""));
    const listed = await listing.preCall({ ...input("notes__read"), method: "tools/list", tool: undefined });
    expect(listed.ruleId).toBe("default:tools/list");
  });
});

function input(tool: string): PreCallInput {
  return {
    sessionId: "s",
    method: "tools/call",
    upstream: "notes",
    tool,
    args: {},
    client: {},
    trusted: false,
    catalog: "ready",
    definition: { name: "read", inputSchema: { type: "object" } },
  };
}
