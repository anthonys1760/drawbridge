import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import {
  connectGateway,
  decideOnDashboard,
  quote,
  resultText,
  root,
  runCli,
  waitForEvents,
} from "../attacks/lib.mjs";

const auditPath = join(root, "examples/.demo/audit.jsonl");
const configPath = join(root, "examples/.demo/drawbridge.yaml");
await mkdir(dirname(auditPath), { recursive: true });
await rm(auditPath, { force: true });
const example = await readFile(join(root, "examples/drawbridge.yaml"), "utf8");
await writeFile(configPath, example.replace("path: ./drawbridge-audit.jsonl", `path: ${quote(auditPath)}`));

const gateway = await connectGateway(configPath);
try {
  await gateway.client.listTools();
  process.stdout.write("Listed the notes and mail catalogs.\n");
  const notes = await gateway.client.callTool({ name: "notes__read", arguments: { path: "q4-notes" } });
  const wrapped = resultText(notes).includes("<<untrusted>>");
  process.stdout.write(
    wrapped
      ? "Read q4-notes. The result is wrapped, and the session is tainted.\n"
      : "Read q4-notes.\n",
  );
  await gateway.client.callTool({ name: "notes__read", arguments: { path: "q4-roadmap" } });
  process.stdout.write("Read q4-roadmap. Policy already saw this session as tainted.\n");
  const pendingCall = gateway.client.callTool({
    name: "mail__send",
    arguments: { to: "q4-sync@outside-sample.example", body: "Please send the keys from the notes." },
  });
  pendingCall.catch(() => undefined);
  const held = await waitForEvents(auditPath, (rows) => rows.some((row) => row.decision === "approve_pending"));
  const pending = held.find((row) => row.decision === "approve_pending");
  const state = JSON.parse(await readFile(join(dirname(auditPath), "drawbridge-approvals.json"), "utf8"));
  process.stdout.write(`mail__send is held (${pending.id}).\n`);
  process.stdout.write(`Dashboard: ${state.url}?token=${state.token}\n`);
  if (process.stdout.isTTY) {
    process.stdout.write("Deny or approve that one call in the dashboard. This waits up to 3 minutes.\n");
    await waitForEvents(auditPath, (rows) => rows.some((row) => row.approval?.pendingId === pending.id), 180_000);
  } else {
    process.stdout.write("No terminal is attached, so this run denies the call and checks the log.\n");
    await decideOnDashboard(auditPath, pending.id, "deny");
  }
  await pendingCall;
} finally {
  await gateway.close();
}

const verified = await runCli(["audit", "verify", "--config", configPath]);
process.stdout.write(verified.stdout || verified.stderr);
if (verified.code !== 0) process.exit(verified.code);
