import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { AttackPath, Row, Stage } from "../api/types";
import { fmtDuration, fmtTime, scoreStages, scoreboard, techniqueMatches, whatIf } from "./logic";

const row = (over: Partial<Row>): Row => ({
  time: 0, class_uid: 3002, activity_id: 1, severity_id: 1, status_id: 1, uid: "u", correlation_uid: null,
  product: "t", hostname: "web01", src_ip: null, user_name: null, process_name: null, process_pid: null,
  cmd_line: null, file_path: null, finding_uid: null, finding_title: null, techniques: [], scenario: null,
  message: null, ...over,
});

describe("scoring mirrors the backend", () => {
  const t = 1_793_005_200_000;
  const stages: Stage[] = [
    { id: "a", name: "A", tactic: "x", techniques: ["T1110.001"], start: t + 1000, host: "web01", description: "" },
    { id: "b", name: "B", tactic: "x", techniques: ["T1078"], start: t + 5000, host: "web01", description: "" },
    { id: "c", name: "C", tactic: "x", techniques: ["T1486"], start: t + 9_000_000, host: "db01", description: "" },
  ];
  const rows = [
    row({ time: t + 1500 }),
    row({ time: t + 4000, class_uid: 2004, techniques: ["T1110"], finding_title: "Brute" }),
    row({ time: t + 5200 }),
  ];

  it("gives detected / telemetry-only / missed with time to detect", () => {
    const s = scoreStages(stages, rows);
    expect(s.map((x) => x.outcome)).toEqual(["detected", "telemetry_only", "missed"]);
    expect(s[0].ttd_ms).toBe(3000);
    expect(scoreboard(s)).toMatchObject({ detected: 1, telemetryOnly: 1, missed: 1, pct: 33, meanTtdS: 3 });
  });

  it("only counts rows already played", () => {
    expect(scoreStages(stages, rows, t + 2000)[0].outcome).toBe("telemetry_only");
    expect(scoreStages(stages, rows, t)[0].outcome).toBe("missed");
  });

  it("agrees with the exported backend score for every recorded scenario", () => {
    for (const id of ["maldoc-to-ransomware", "ssh-bruteforce-to-persistence"]) {
      let sc, backend;
      try {
        sc = JSON.parse(readFileSync(`public/demo/scenario/${id}.json`, "utf-8"));
        backend = JSON.parse(readFileSync(`public/demo/score/${id}.json`, "utf-8"));
      } catch {
        continue; // demo data not exported yet
      }
      const ours = scoreStages(sc.stages, sc.events);
      expect(ours.map((s) => [s.stage, s.outcome, s.ttd_ms])).toEqual(
        backend.stages.map((s: { stage: string; outcome: string; ttd_ms: number | null }) => [s.stage, s.outcome, s.ttd_ms]),
      );
    }
  });
});

describe("helpers", () => {
  it("matches parent and sub-techniques", () => {
    expect(techniqueMatches("T1110", "T1110.003")).toBe(true);
    expect(techniqueMatches("T1110.001", "T1110.003")).toBe(false);
  });

  it("formats durations and times", () => {
    expect(fmtDuration(null)).toBe("n/a");
    expect(fmtDuration(42)).toBe("42s");
    expect(fmtDuration(726)).toBe("12m 6s");
    expect(fmtDuration(7300)).toBe("2h 1m");
    expect(fmtTime(1_793_005_200_000)).toBe("09:00:00Z");
  });

  it("computes what-if attack paths", () => {
    const paths: AttackPath[] = [
      { target: "db", probability: 0.5, path: [], steps: [{ from: "i", to: "web", port: 80, cve: "CVE-1" }] },
      { target: "fs", probability: 0.5, path: [], steps: [{ from: "i", to: "app", port: 80, cve: "CVE-2" }] },
    ];
    expect(whatIf(paths, new Set(["CVE-1"]))).toMatchObject({ before: 2, after: 1, reachable: ["fs"] });
  });
});
