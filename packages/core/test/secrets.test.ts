import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { createScrubber, envForStdio, headersForHttp, resolveUpstreamSecrets, stripClientCredentials } from "../src/index.js";
import type { UpstreamConfig } from "../src/config.js";

const ALPHA = "seed-alpha-secret-aaaa";
const BETA = "seed-beta-secret-bbbb";

function stdio(secrets?: Record<string, string>): UpstreamConfig {
  return {
    transport: "stdio",
    command: ["node", "server.js"],
    trusted: false,
    pinTools: false,
    onPinMismatch: "deny",
    ...(secrets ? { secrets } : {}),
  };
}

describe("per-upstream secrets", () => {
  it("resolves env and file refs without leaking one upstream into the other", async () => {
    const resolved = await resolveUpstreamSecrets(
      [
        { name: "notes", upstream: stdio({ NOTES_TOKEN: "env:NOTES_TOKEN" }) },
        { name: "mail", upstream: stdio({ MAIL_TOKEN: "file:/run/mail-token" }) },
      ],
      { NOTES_TOKEN: ALPHA },
      async (path) => {
        if (path === "/run/mail-token") return `${BETA}\n`;
        throw new Error(`unexpected ${path} containing ${ALPHA}`);
      },
    );
    expect(resolved.get("notes")).toEqual({ NOTES_TOKEN: ALPHA });
    expect(resolved.get("mail")).toEqual({ MAIL_TOKEN: BETA });
    const notesEnv = envForStdio({}, undefined, resolved.get("notes") ?? {});
    const mailEnv = envForStdio({}, undefined, resolved.get("mail") ?? {});
    expect(notesEnv.NOTES_TOKEN).toBe(ALPHA);
    expect(notesEnv.MAIL_TOKEN).toBeUndefined();
    expect(mailEnv.MAIL_TOKEN).toBe(BETA);
    expect(mailEnv.NOTES_TOKEN).toBeUndefined();
    expect(headersForHttp({ Accept: "application/json" }, resolved.get("mail") ?? {}).MAIL_TOKEN).toBe(BETA);
    expect(headersForHttp(undefined, resolved.get("notes") ?? {}).MAIL_TOKEN).toBeUndefined();
  });

  it("refuses a missing env var and a missing file without echoing another secret", async () => {
    await expect(
      resolveUpstreamSecrets([{ name: "notes", upstream: stdio({ NOTES_TOKEN: "env:MISSING_TOKEN" }) }], {}, async () => ALPHA),
    ).rejects.toThrow(/MISSING_TOKEN/);
    try {
      await resolveUpstreamSecrets([{ name: "notes", upstream: stdio({ NOTES_TOKEN: "env:MISSING_TOKEN" }) }], { OTHER: ALPHA }, async () => BETA);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      expect(message).not.toContain(ALPHA);
      expect(message).not.toContain(BETA);
    }
    try {
      await resolveUpstreamSecrets([{ name: "mail", upstream: stdio({ MAIL_TOKEN: "file:/missing" }) }], {}, async () => {
        throw new Error(`open failed ${BETA}`);
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      expect(message).toMatch(/Cannot read secret file/);
      expect(message).not.toContain(BETA);
    }
  });

  it("gives a child process only its own secret", () => {
    const env = envForStdio({ PATH: process.env.PATH }, {}, { ONLY_A: ALPHA });
    const seen = spawnSync(process.execPath, ["-e", "process.stdout.write((process.env.ONLY_A ?? '') + '|' + (process.env.ONLY_B ?? ''))"], {
      env,
      encoding: "utf8",
    });
    expect(seen.stdout).toBe(`${ALPHA}|`);
    expect(process.env.ONLY_A).toBeUndefined();
  });

  it("scrubs known secrets and strips client credential keys", () => {
    expect(createScrubber([ALPHA, BETA])(`failed ${BETA} then ${ALPHA}`)).toBe("failed [REDACTED] then [REDACTED]");
    const stripped = stripClientCredentials({ message: "hi", token: ALPHA, nested: { api_key: BETA } });
    expect(stripped.args).toEqual({ message: "hi", nested: {} });
    expect(stripped.paths).toEqual(["token", "nested.api_key"]);
    expect(JSON.stringify(stripped)).not.toContain(ALPHA);
  });
});
