import clsx from "clsx";
import { useEffect, useMemo, useState } from "react";
import type { CoverageCell, CoverageOutcome } from "../api/types";
import { Card, Empty, ErrorBox, Kpi, Loading, OutcomeChip, PageHeader, Tag } from "../components/ui";
import { useLoad } from "../lib/data";
import { fmtDuration, fmtNumber, fmtTime } from "../lib/logic";

const TACTICS = [
  "reconnaissance", "resource-development", "initial-access", "execution", "persistence", "privilege-escalation",
  "defense-evasion", "credential-access", "discovery", "lateral-movement", "collection", "command-and-control",
  "exfiltration", "impact",
];

const norm = (t?: string) => (t ?? "unknown").toLowerCase().replace(/[\s_]+/g, "-");
const CELL: Record<string, string> = {
  detected: "border-good/60 bg-good/15 text-good",
  telemetry_only: "border-warn/60 bg-warn/15 text-warn",
  missed: "border-bad/60 bg-bad/15 text-bad",
  prevented: "border-status-prevented/60 bg-status-prevented/15 text-status-prevented",
  error: "border-status-error/60 bg-status-error/15 text-status-error",
  skipped: "border-line bg-panel-2 text-muted",
};

const EXPLAIN: Record<CoverageOutcome, string> = {
  detected: "A rule fired inside the scoring window.",
  prevented: "The endpoint's protection blocked it. Counted as covered, but check a rule would still catch it if the block failed.",
  telemetry_only: "Events arrived. Write or tune a rule in 08 to close this gap.",
  missed: "No events arrived. Check the sensor and log source first.",
  error: "The technique did not run cleanly, so this cell says nothing about detection. Fix the lab and run it again.",
  skipped: "Not executed (dry run, or no hub to score against).",
};

export default function Coverage() {
  const runs = useLoad((s) => s.coverageRuns());
  const [runId, setRunId] = useState<string | null>(null);
  useEffect(() => {
    if (!runId && runs.data?.length) setRunId(runs.data[0].id);
  }, [runs.data, runId]);
  const matrix = useLoad((s) => (runId ? s.coverage(runId) : Promise.resolve(null)), [runId]);
  const [sel, setSel] = useState<CoverageCell | null>(null);

  const columns = useMemo(() => {
    const cells = matrix.data?.cells ?? [];
    const known = TACTICS.map((t) => ({ tactic: t, cells: cells.filter((c) => norm(c.tactic) === t) }));
    const other = cells.filter((c) => !TACTICS.includes(norm(c.tactic)));
    return [...known.filter((k) => k.cells.length), ...(other.length ? [{ tactic: "other", cells: other }] : [])];
  }, [matrix.data]);

  if (runs.error) return <ErrorBox error={runs.error} />;
  if (!runs.data) return <Loading />;
  if (!runs.data.length) return <Empty quipKey="coverage">No coverage runs yet. Run 07-attack-emulator or 05-purple-team-lab and point WF_COVERAGE_DIR at the results.</Empty>;
  const m = matrix.data;
  const count = (...o: CoverageOutcome[]) => m?.cells.filter((c) => o.includes(c.outcome)).length ?? 0;
  const counts = m ? { d: count("detected", "prevented"), p: count("prevented"), t: count("telemetry_only"), x: count("missed") } : null;

  return (
    <>
      <PageHeader title="ATT&CK coverage"
        actions={<select value={runId ?? ""} onChange={(e) => { setRunId(e.target.value); setSel(null); }} aria-label="Coverage run"
          className="border border-line bg-panel-2 px-3 py-1.5 text-sm">
          {runs.data.map((r) => <option key={r.id} value={r.id}>{r.title} ({r.kind})</option>)}
        </select>}>
        Every technique the emulator ran, scored the same way as scenario playback: a finding fired (detected), the
        endpoint blocked it (prevented), the events reached the lake but nothing fired (telemetry only), or nothing
        arrived (missed).
      </PageHeader>
      {matrix.error ? <ErrorBox error={matrix.error} /> : !m || !counts ? <Loading /> : (
        <>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <Kpi label="Detection coverage" value={`${fmtNumber(m.summary.detection_coverage)}%`} tone={m.summary.detection_coverage >= 75 ? "good" : "warn"} />
            <Kpi label="Detected" value={counts.d} tone="good" hint={counts.p ? `${counts.p} of them prevented` : undefined} />
            <Kpi label="Telemetry only" value={counts.t} tone={counts.t ? "warn" : "default"} hint="rule work needed" />
            <Kpi label="Missed" value={counts.x} tone={counts.x ? "bad" : "default"} hint="sensor work needed" />
          </div>
          <div className="mt-4 grid gap-4 xl:grid-cols-4">
            <Card className="xl:col-span-3" title={m.title} subtitle="Click a technique for details">
              <div className="flex gap-2 overflow-x-auto pb-2">
                {columns.map((col) => (
                  <div key={col.tactic} className="w-40 shrink-0">
                    <div className="mb-2 border-b border-line pb-1 text-[11px] font-semibold uppercase tracking-wider text-muted">{col.tactic.replace(/-/g, " ")}</div>
                    <div className="space-y-1.5">
                      {col.cells.map((c, i) => (
                        <button key={`${c.technique}-${i}`} type="button" onClick={() => setSel(c)}
                          className={clsx("w-full border px-2 py-1.5 text-left transition hover:brightness-125", CELL[c.outcome], sel === c && "ring-2 ring-accent")}>
                          <div className="font-mono text-[11px] font-semibold">{c.technique}</div>
                          <div className="truncate text-[11px] text-ink/80">{c.name ?? c.test ?? ""}</div>
                        </button>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </Card>
            <Card title={sel ? sel.technique : "Technique"}>
              {sel ? (
                <div className="space-y-2 text-sm">
                  <div className="font-medium">{sel.name}</div>
                  <div className="flex flex-wrap gap-1.5"><OutcomeChip outcome={sel.outcome} />{sel.tactic && <Tag>{sel.tactic}</Tag>}{sel.source_outcome && <Tag mono>{sel.source_outcome}</Tag>}</div>
                  {sel.test && <p className="text-xs text-muted">Test: {sel.test}</p>}
                  {sel.target && <p className="text-xs text-muted">Target: <span className="font-mono">{sel.target}</span></p>}
                  {sel.ttd_ms !== undefined && sel.ttd_ms !== null && <p className="text-xs">Time to detect: <span className="font-mono">{fmtDuration(sel.ttd_ms / 1000)}</span></p>}
                  {!!sel.findings?.length && <ul className="list-disc pl-4 text-xs">{sel.findings.map((f, i) => <li key={i}>{f.title} <Tag>{f.product}</Tag></li>)}</ul>}
                  <p className="text-xs text-muted">{EXPLAIN[sel.outcome] ?? ""}</p>
                </div>
              ) : <Empty>Select a technique.</Empty>}
            </Card>
          </div>
          <Card className="mt-4" title="All runs">
            <table className="w-full text-sm">
              <thead className="text-left text-[11px] uppercase text-muted"><tr><th className="py-1">Run</th><th>Kind</th><th>Started</th><th className="text-right">Detection</th><th className="text-right">Telemetry</th></tr></thead>
              <tbody className="divide-y divide-line">
                {runs.data.map((r) => (
                  <tr key={r.id} className={clsx(r.id === runId && "bg-accent/5")}>
                    <td className="py-1.5"><button type="button" className="text-accent hover:underline" onClick={() => setRunId(r.id)}>{r.title}</button></td>
                    <td><Tag>{r.kind}</Tag></td><td className="font-mono text-xs">{r.started ? fmtTime(r.started, true) : "n/a"}</td>
                    <td className="text-right font-mono">{fmtNumber(r.detection_coverage)}%</td>
                    <td className="text-right font-mono">{r.telemetry_coverage === null ? "n/a" : `${fmtNumber(r.telemetry_coverage)}%`}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        </>
      )}
    </>
  );
}
