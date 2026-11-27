import { readdir, readFile } from "node:fs/promises";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const skip = new Set(["node_modules", "dist", ".git", "coverage"]);
const patterns = [
  { name: "private-key", re: /-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----/ },
  { name: "aws-access-key", re: /AKIA[0-9A-Z]{16}/ },
  { name: "github-token", re: /ghp_[A-Za-z0-9]{20,}/ },
  { name: "slack-token", re: /xox[baprs]-[A-Za-z0-9-]{10,}/ },
];

const hits = [];
await walk(root);
if (hits.length > 0) {
  for (const hit of hits) process.stderr.write(`${hit}\n`);
  process.exit(1);
}

async function walk(dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (skip.has(entry.name)) continue;
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      await walk(path);
      continue;
    }
    if (entry.name === "scan-secrets.mjs" || entry.name === "pnpm-lock.yaml") continue;
    let text = "";
    try {
      text = await readFile(path, "utf8");
    } catch {
      continue;
    }
    for (const pattern of patterns) {
      if (pattern.re.test(text)) hits.push(`${relative(root, path)} matches ${pattern.name}`);
    }
  }
}
