// Pure helpers shared by pages. Scoring and what-if mirror watchfloor/scenarios.py and hub/artifacts.py,
// so the browser playback reaches the same verdict as the backend (tested in logic.test.ts).

import type { AttackPath, Outcome, Row, Stage, StageScore } from "../api/types";

export const SEVERITY = ["unknown", "info", "low", "medium", "high", "critical", "fatal"] as const;

export const CLASS_NAMES: Record<number, string> = {
  1001: "File activity",
  1007: "Process activity",
  2004: "Detection finding",
  2005: "Incident finding",
  3001: "Account change",
  3002: "Authentication",
  4001: "Network activity",
};

export function severityName(id: number | null | undefined): string {
  return SEVERITY[id ?? 0] ?? "unknown";
}

export function fmtDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || Number.isNaN(seconds)) return "n/a";
  const s = Math.round(seconds);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

export function fmtTime(ms: number, withDate = false): string {
  const iso = new Date(ms).toISOString();
  return withDate ? `${iso.slice(0, 10)} ${iso.slice(11, 19)}Z` : `${iso.slice(11, 19)}Z`;
}

export function fmtNumber(n: number | null | undefined): string {
  if (n === null || n === undefined) return "n/a";
  return new Intl.NumberFormat("en", { maximumFractionDigits: 1 }).format(n);
}

export function techniqueMatches(stageTech: string, findingTech: string): boolean {
  const a = stageTech.toUpperCase();
  const b = findingTech.toUpperCase();
  return a === b || a.split(".")[0] === b || b.split(".")[0] === a;
}

const WINDOW_MS = 15 * 60 * 1000;

/** Score stages against the rows seen so far (rows after `until` are ignored: that is what makes playback live). */
export function scoreStages(stages: Stage[], rows: Row[], until = Number.POSITIVE_INFINITY): StageScore[] {
  const visible = rows.filter((r) => r.time <= until);
  const findings = visible.filter((r) => r.class_uid === 2004);
  const activity = visible.filter((r) => r.class_uid !== 2004 && r.class_uid !== 2005);
  return stages.map((st) => {
    const end = st.start + WINDOW_MS;
    const hits = findings
      .filter((f) => f.time >= st.start - 1000 && f.time <= end)
      .filter((f) => st.techniques.some((t) => f.techniques.some((ft) => techniqueMatches(t, ft))))
      .sort((a, b) => a.time - b.time);
    const telemetry = activity.filter(
      (e) => e.time >= st.start - 1000 && e.time <= end && (!st.host || e.hostname === st.host),
    );
    let outcome: Outcome = hits.length ? "detected" : telemetry.length ? "telemetry_only" : "missed";
    if (until < st.start) outcome = "missed";
    return {
      stage: st.id,
      name: st.name,
      tactic: st.tactic,
      techniques: st.techniques,
      start: st.start,
      outcome,
      ttd_ms: hits.length ? Math.max(0, hits[0].time - st.start) : null,
      findings: hits.slice(0, 10).map((f) => ({ uid: f.uid, title: f.finding_title ?? "", product: f.product ?? "", time: f.time })),
      telemetry_events: telemetry.length,
    };
  });
}

export function scoreboard(scores: StageScore[]) {
  const detected = scores.filter((s) => s.outcome === "detected");
  const ttds = detected.map((s) => s.ttd_ms ?? 0);
  return {
    detected: detected.length,
    telemetryOnly: scores.filter((s) => s.outcome === "telemetry_only").length,
    missed: scores.filter((s) => s.outcome === "missed").length,
    total: scores.length,
    pct: scores.length ? Math.round((detected.length / scores.length) * 100) : 0,
    meanTtdS: ttds.length ? ttds.reduce((a, b) => a + b, 0) / ttds.length / 1000 : null,
  };
}

export function whatIf(paths: AttackPath[], patched: Set<string>) {
  const alive = paths.filter((p) => !p.steps.some((s) => patched.has((s.cve ?? "").toUpperCase())));
  return { before: paths.length, after: alive.length, alive, reachable: [...new Set(alive.map((p) => p.target))].sort() };
}

export const OUTCOME_LABEL: Record<Outcome, string> = {
  detected: "Detected",
  telemetry_only: "Telemetry only",
  missed: "Missed",
};
