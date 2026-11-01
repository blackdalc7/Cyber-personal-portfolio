import { describe, expect, it } from "vitest";
import {
  KONAMI, analystStress, complete, hexdumpLine, konamiStep, parseCommand, quipFor, rng, scrambleFrame,
} from "./logic";

describe("scrambleFrame", () => {
  it("reveals left to right and ends on the target", () => {
    const r = rng(1);
    expect(scrambleFrame("ISOLATE", 1, r)).toBe("ISOLATE");
    const half = scrambleFrame("ISOLATE", 0.5, r);
    expect(half.slice(0, 3)).toBe("ISO");
    expect(half).toHaveLength(7);
  });
  it("keeps spaces so word shapes stay readable", () => {
    expect(scrambleFrame("a b", 0, rng(2))[1]).toBe(" ");
  });
});

describe("konami", () => {
  it("fires only on the full sequence and recovers from a wrong key", () => {
    let pos = 0;
    let done = false;
    for (const k of ["ArrowUp", "x", ...KONAMI]) ({ position: pos, done } = konamiStep(pos, k));
    expect(done).toBe(true);
    expect(pos).toBe(0);
  });
  it("accepts upper-case B and A", () => {
    let pos = 0;
    let done = false;
    for (const k of [...KONAMI.slice(0, 8), "B", "A"]) ({ position: pos, done } = konamiStep(pos, k));
    expect(done).toBe(true);
  });
});

describe("analystStress", () => {
  it("is calm with nothing happening and saturates under load", () => {
    expect(analystStress({ alertsPerHour: 0, openIncidents: 0 }).level).toBe("zen");
    const hot = analystStress({ alertsPerHour: 500, openIncidents: 20, critical: 40, mttaSeconds: 7200 });
    expect(hot.score).toBeGreaterThan(90);
    expect(hot.level).toBe("sleeping-under-desk");
    expect(hot.cups).toBe(6);
  });
  it("cannot be pinned by one input alone", () => {
    expect(analystStress({ alertsPerHour: 1e6, openIncidents: 0 }).score).toBeLessThanOrEqual(40);
  });
});

describe("terminal parsing", () => {
  it("splits words, quotes and flags", () => {
    expect(parseCommand(`/isolate web01 --reason "brute force" --dry-run`)).toEqual({
      name: "isolate", args: ["web01"], flags: { reason: "brute force", "dry-run": true },
    });
    expect(parseCommand("/run dw-win --tag=lab").flags).toEqual({ tag: "lab" });
  });
  it("completes to the longest common prefix", () => {
    expect(complete("/inc", ["incidents", "incident", "isolate"])).toEqual({ completion: "/incident", matches: ["incident", "incidents"] });
    expect(complete("zz", ["a"]).matches).toEqual([]);
  });
});

it("quipFor is stable per key", () => {
  expect(quipFor("findings")).toBe(quipFor("findings"));
});

it("hexdumpLine formats like xxd", () => {
  expect(hexdumpLine(16, [0x41, 0x00, 0x7a])).toBe(`00000010  41 00 7a${" ".repeat(39)}  |A.z|`);
});
