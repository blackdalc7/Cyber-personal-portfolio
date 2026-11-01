import { CountUp, DataWaterfall, GlitchText, StressGauge } from "@portfolio/aegis-ui";
import { ArrowRight, Radio } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import type { Row } from "../api/types";
import { EChart, chartColors, useThemeVersion } from "../components/EChart";
import { Card, ErrorBox, Kpi, Loading, PageHeader, Severity, Tag } from "../components/ui";
import { useLoad, useSource } from "../lib/data";
import { fmtDuration, fmtNumber, fmtTime } from "../lib/logic";

export default function WatchFloor() {
  const src = useSource();
  const summary = useLoad((s) => s.summary());
  const findings = useLoad((s) => s.findings());
  const triage = useLoad((s) => s.triage());
  const coverage = useLoad((s) => s.coverageRuns());
  const theme = useThemeVersion();
  const [live, setLive] = useState<Row[]>([]);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    if (!src.subscribe) return;
    return src.subscribe((row) => setLive((l) => [row, ...l].slice(0, 200)), setConnected);
  }, [src]);

  const stream = useMemo(() => {
    const base = (findings.data ?? []).slice().sort((a, b) => b.time - a.time);
    return [...live.filter((r) => r.class_uid === 2004), ...base].slice(0, 40);
  }, [findings.data, live]);

  // Background "data waterfall": live rows as they stream in, or the recorded findings on loop in replay mode.
  const waterfall = useMemo(() => {
    const fmt = (r: Row) => `${fmtTime(r.time)} ${r.class_uid === 2004 ? "FINDING" : `ocsf:${r.class_uid}`} ${r.hostname ?? ""} ${
      r.finding_title ?? r.message ?? r.cmd_line ?? r.user_name ?? ""}`;
    return [...(findings.data ?? []).map(fmt), ...live.slice().reverse().map(fmt)];
  }, [findings.data, live]);

  const options = useMemo(() => {
    const s = summary.data;
    if (!s) return null;
    const c = chartColors();
    const axis = { axisLine: { lineStyle: { color: c.line } }, axisLabel: { color: c.muted, fontSize: 10 }, splitLine: { lineStyle: { color: c.line, opacity: 0.4 } } };
    const funnelMax = Math.max(...s.funnel.map((f) => f.count), 1);
    return {
      funnel: {
        grid: { left: 130, right: 60, top: 8, bottom: 8 },
        xAxis: { type: "log", show: false, min: 0.8, max: funnelMax * 1.2 },
        yAxis: { type: "category", inverse: true, data: s.funnel.map((f) => f.stage), axisLabel: { color: c.ink, fontSize: 12 }, axisLine: { show: false }, axisTick: { show: false } },
        tooltip: { trigger: "item" },
        series: [{ type: "bar", barWidth: 18, data: s.funnel.map((f, i) => ({ value: Math.max(f.count, 0.9), itemStyle: { color: i === 0 ? c.muted : i === s.funnel.length - 1 ? c.good : c.accent, borderRadius: 4 } })),
          label: { show: true, position: "right", color: c.ink, fontFamily: "JetBrains Mono", formatter: (p: { dataIndex: number }) => fmtNumber(s.funnel[p.dataIndex].count) } }],
      },
      histogram: {
        grid: { left: 36, right: 12, top: 24, bottom: 28 },
        legend: { top: 0, right: 0, textStyle: { color: c.muted, fontSize: 11 }, itemWidth: 10, itemHeight: 10 },
        tooltip: { trigger: "axis" },
        xAxis: { type: "time", ...axis, splitLine: { show: false } },
        yAxis: [{ type: "value", ...axis }, { type: "value", ...axis, splitLine: { show: false } }],
        series: [
          { name: "Activity events", type: "bar", data: s.histogram.map((h) => [h.bucket, h.events]), itemStyle: { color: c.muted, opacity: 0.55 }, barMaxWidth: 6 },
          { name: "Findings", type: "scatter", yAxisIndex: 1, symbolSize: 9, data: s.histogram.filter((h) => h.findings).map((h) => [h.bucket, h.findings]), itemStyle: { color: c.bad } },
        ],
      },
      severity: {
        tooltip: { trigger: "item" },
        series: [{ type: "pie", radius: ["55%", "80%"], itemStyle: { borderColor: c.panel, borderWidth: 2 },
          label: { color: c.ink, formatter: "{b}\n{c}", fontSize: 11 },
          data: Object.entries(s.findings_by_severity).map(([k, v]) => ({ name: k, value: v,
            itemStyle: { color: { critical: c.crit, high: c.bad, medium: c.warn, low: c.accent }[k] ?? c.muted } })) }],
      },
      techniques: {
        grid: { left: 80, right: 30, top: 4, bottom: 4 },
        xAxis: { type: "value", show: false },
        yAxis: { type: "category", inverse: true, data: s.top_techniques.map((t) => t.technique), axisLabel: { color: c.ink, fontFamily: "JetBrains Mono", fontSize: 11 }, axisLine: { show: false }, axisTick: { show: false } },
        series: [{ type: "bar", barWidth: 10, data: s.top_techniques.map((t) => t.n), itemStyle: { color: c.accent, borderRadius: 3 }, label: { show: true, position: "right", color: c.muted, fontSize: 10 } }],
      },
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [summary.data, theme]);

  if (summary.error) return <ErrorBox error={summary.error} />;
  if (!summary.data || !options) return <Loading />;
  const k = summary.data.kpis;
  const latestCoverage = coverage.data?.[0];

  return (
    <>
      <DataWaterfall lines={waterfall} />
      <PageHeader title="Watch floor"
        actions={<Link to="/scenarios" className="inline-flex items-center gap-1.5 border border-cyan bg-cyan/10 px-3 py-1.5 font-mono text-xs uppercase tracking-wider text-cyan hover:bg-cyan/20 hover:shadow-[var(--ae-glow)]"><GlitchText text="Play an attack" /> <ArrowRight className="h-4 w-4" /></Link>}>
        Every event below arrived as OCSF on the spine. {src.mode === "replay"
          ? "This is the replay demo: recorded datasets from projects 01, 02, 03, 04, 05 and 06."
          : "Live data from the lake; new findings stream in at the top."}
      </PageHeader>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Kpi label="Activity events" value={k.events} hint="auth, process, file, account" />
        <Kpi label="Findings" value={k.findings} hint="from 01, 03, 08" tone={k.findings ? "warn" : "default"} />
        <Kpi label="Incidents" value={k.incidents} hint={`${k.open_incidents} open`} tone={k.open_incidents ? "bad" : "good"} />
        <Kpi label="Mean time to approve" value={k.mtta_s} format={fmtDuration} hint="detection → human decision" />
        <Kpi label="Mean time to contain" value={k.mttr_s} format={fmtDuration} hint="detection → isolated" />
        <Kpi label="ATT&CK coverage" value={latestCoverage ? latestCoverage.detection_coverage : null} format={(n) => `${fmtNumber(n)}%`}
          hint={latestCoverage ? latestCoverage.title : "run 07 or 05"} tone={latestCoverage && latestCoverage.detection_coverage >= 75 ? "good" : "warn"} />
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2" scanlines title="From noise to containment" subtitle="Log scale. Each step is a project in the loop.">
          <EChart option={options.funnel} height={190} ariaLabel="Funnel from activity events to contained incidents" />
        </Card>
        <Card scanlines title="Finding severity">
          <EChart option={options.severity} height={190} ariaLabel="Findings by severity" />
        </Card>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2" scanlines title="Activity and findings over time" subtitle="Per minute, across the recorded scenarios">
          <EChart option={options.histogram} height={220} ariaLabel="Events and findings per minute" />
        </Card>
        <Card scanlines title="Top ATT&CK techniques in findings">
          <EChart option={options.techniques} height={220} ariaLabel="Most frequent techniques" />
        </Card>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2" title="Finding stream"
          actions={src.mode === "live" ? (
            <span className={`flex items-center gap-1 text-xs ${connected ? "text-good" : "text-muted"}`}><Radio className="h-3.5 w-3.5" />{connected ? "streaming" : "connecting"}</span>
          ) : <Tag>recorded</Tag>}>
          {!stream.length && <p className="py-6 text-center font-mono text-sm text-muted">0 alerts found. Either the firewall is working, or it's unplugged.</p>}
          <ul className="divide-y divide-line">
            {stream.map((f) => (
              <li key={f.uid} className="ae-in flex items-center gap-3 py-2 text-sm hover:bg-white/[0.02]">
                <span className="w-20 shrink-0 font-mono text-xs text-muted">{fmtTime(f.time)}</span>
                <Severity id={f.severity_id} />
                <span className="min-w-0 flex-1 truncate">{f.finding_title}</span>
                <span className="hidden shrink-0 font-mono text-xs text-muted sm:inline">{f.hostname}</span>
                <Tag>{f.product}</Tag>
              </li>
            ))}
          </ul>
        </Card>
        <div className="space-y-4">
          <Card title="Analyst stress index" subtitle="Alert rate, open incidents, criticals and approval latency, blended">
            <StressGauge alertsPerHour={k.findings} openIncidents={k.open_incidents}
              critical={summary.data.findings_by_severity.critical ?? 0} mttaSeconds={k.mtta_s} />
          </Card>
          <TriageCard triage={triage.data ?? null} />
        </div>
      </div>
    </>
  );
}

function TriageCard({ triage }: { triage: import("../api/types").TriageData | null }) {
  if (!triage) {
    return (
      <Card title="Noise reduction (06)">
        <p className="text-sm text-muted">Point WF_TRIAGE_QUEUE at 06's queue.json to show its clustering results here.</p>
      </Card>
    );
  }
  const m = triage.metrics;
  const e = triage.evaluation;
  return (
    <Card title="Noise reduction (06)" subtitle={`06's example run on ${fmtNumber(m.raw_alerts)} simulated alerts`}>
      <div className="grid grid-cols-3 gap-2 text-center">
        <div><div className="font-mono text-xl font-semibold"><CountUp value={m.raw_alerts} /></div><div className="text-[11px] text-muted">raw alerts</div></div>
        <div><div className="font-mono text-xl font-semibold"><CountUp value={m.meta_alerts} /></div><div className="text-[11px] text-muted">meta-alerts</div></div>
        <div><div className="ae-neon-text font-mono text-xl font-semibold text-green"><CountUp value={m.analyst_queue} /></div><div className="text-[11px] text-muted">to an analyst</div></div>
      </div>
      <dl className="mt-4 space-y-1.5 text-sm">
        <div className="flex justify-between"><dt className="text-muted">True-threat recall</dt><dd className="font-mono">{(e.true_threat_recall * 100).toFixed(0)}%</dd></div>
        <div className="flex justify-between"><dt className="text-muted">Suppression precision</dt><dd className="font-mono">{(e.suppression_precision * 100).toFixed(0)}%</dd></div>
        <div className="flex justify-between"><dt className="text-muted">Analyst time (est.)</dt><dd className="font-mono">{m.analyst_hours_before}h → {m.analyst_hours_after}h</dd></div>
      </dl>
      <p className="mt-3 text-[11px] text-muted">Labelled, simulated data ({fmtNumber(e.labelled_alerts)} alerts). Time estimate uses 06's stated minutes-per-alert assumptions.</p>
    </Card>
  );
}
