import { describe, expect, it } from "vitest";
import { chainSteps, countdownLabel, defaultSelection, renderArgs, timeoutAnnouncements } from "../src/view.ts";

const address = "q•••@outside-sample.example";

describe("dashboard view", () => {
  it("selects the first pending call only when nothing is selected", () => {
    expect(defaultSelection(null, ["a", "b"], [])).toBe("a");
    expect(defaultSelection("b", ["a", "b"], [])).toBe("b");
    expect(defaultSelection("decided", ["c"], ["decided"])).toBe("decided");
    expect(defaultSelection("gone", ["c"], [])).toBe("c");
  });

  it("marks the hit path, not an earlier copy of the same address", () => {
    const pieces = renderArgs(
      { body: `see ${address} in the note`, to: address },
      [{ rule: "exfil.untrusted-data", path: "to", span: [0, address.length] }],
    );
    const marked = pieces.filter((piece) => piece.hit).map((piece) => piece.text).join("");
    expect(marked).toBe(address);
    const plain = pieces.filter((piece) => !piece.hit).map((piece) => piece.text).join("");
    expect(plain).toContain(`see ${address} in the note`);
    expect(plain.match(new RegExp(address, "g"))).toHaveLength(1);
  });

  it("shows the read that tainted the session, not the pending send's exfil verdict", () => {
    const steps = chainSteps(
      {
        tool: "mail__send",
        taint: { tainted: true, sources: ["notes"] },
        scanner: { verdict: "flagged", hits: [{ rule: "exfil.untrusted-data" }] },
      },
      [
        {
          tool: "notes__read",
          upstream: "notes",
          taintAfter: { tainted: true, sources: ["notes"] },
          scanner: { verdict: "wrapped", hits: [{ rule: "instruction-override" }, { rule: "role-hijack" }] },
        },
      ],
    );
    expect(steps[0]).toBe("Untrusted read · notes__read");
    expect(steps[1]).toBe("Scanner · instruction-override, role-hijack");
    expect(steps.join(" ")).not.toContain("exfil");
  });

  it("announces a timeout once, naming the tool", () => {
    const events = [{ id: "pending", decision: "approve_pending", tool: "mail__send" }, { id: "done", decision: "timeout", tool: "mail__send" }];
    expect(timeoutAnnouncements(events, new Set())).toEqual(["mail__send timed out and was denied."]);
    expect(timeoutAnnouncements(events, new Set(["done"]))).toEqual([]);
    expect(countdownLabel(84)).toBe("1:24");
    expect(countdownLabel(9)).toBe("0:09");
  });
});