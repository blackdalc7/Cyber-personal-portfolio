import clsx from "clsx";
import { ChevronLeft, Lightbulb, Pause, Play, RotateCcw, SkipForward } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import type { Row, StageScore } from "../api/types";
import { Button, Card, ErrorBox, Kpi, Loading, OutcomeChip, PageHeader, Severity, Tag } from "../components/ui";
import { useLoad } from "../lib/data";
import { CLASS_NAMES, fmtDuration, fmtTime, scoreStages, scoreboard } from "../lib/logic";

const SPEEDS = [10, 60, 300, 1200];

/** Replays a recorded scenario on a virtual clock and scores each stage as the events arrive. */
export default function Playback() {
  const { id = "" } = useParams();
  const scenario = useLoad((s) => s.scenario(id), [id]);
  const [cursor, setCursor] = useState<number | null>(null);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(60);
  const [selected, setSelected] = useState<string | null>(null);
  const last = useRef<number | null>(null);

  const bounds = useMemo(() => {
    const ev = scenario.data?.events ?? [];
    if (!ev.length) return null;
    const first = Math.min(...ev.map((e) => e.time), ...(scenario.data?.stages.map((s) => s.start) ?? []));
    const end = Math.max(...ev.map((e) => e.time));
    return { start: first - 1000, end: end + 1000 };
  }, [scenario.data]);

  useEffect(() => {
    if (bounds) setCursor(bounds.start);
  }, [bounds]);

  useEffect(() => {
    if (!playing || !bounds) return;
    let frame = 0;
    const tick = (now: number) => {
      const dt = last.current === null ? 0 : now - last.current;
      last.current = now;
      setCursor((c) => {
        const next = Math.min((c ?? bounds.start) + dt * speed, bounds.end);
        if (next >= bounds.end) setPlaying(false);
        return next;
      });
      frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => {
      cancelAnimationFrame(frame);
      last.current = null;
    };
  }, [playing, speed, bounds]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.target as HTMLElement).closest("input, textarea, select")) return;
      if (e.key === " ") {
        e.preventDefault();
        setPlaying((p) => !p);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const data = scenario.data;
  const now = cursor ?? 0;
  const visible = useMemo(() => (data ? data.events.filter((e) => e.time <= now) : []), [data, now]);
  const scores = useMemo(() => (data ? scoreStages(data.stages, data.events, now) : []), [data, now]);
  const board = scoreboard(scores);
  const finished = !!bounds && now >= bounds.end;

  if (scenario.error) return <ErrorBox error={scenario.error} />;
  if (!data || !bounds || cursor === null) return <Loading />;

  const pct = ((now - bounds.start) / (bounds.end - bounds.start)) * 100;
  const feed = visible.slice(-60).reverse();
  const focus = scores.find((s) => s.stage === selected) ?? null;
  const restart = () => {
    setCursor(bounds.start);
    setPlaying(true);
  };

  return (
    <>
      <Link to="/scenarios" className="mb-2 inline-flex items-center gap-1 text-xs text-muted hover:text-ink">
        <ChevronLeft className="h-3.5 w-3.5" /> All scenarios
      </Link>
      <PageHeader title={data.title}
        actions={<>
          <Button variant="primary" onClick={() => (finished ? restart() : setPlaying(!playing))} ariaLabel={playing ? "Pause" : "Play"}>
            {playing ? <Pause className="h-4 w-4" /> : finished ? <RotateCcw className="h-4 w-4" /> : <Play className="h-4 w-4" />}
            {playing ? "Pause" : finished ? "Replay" : "Play"}
          </Button>
          <Button onClick={() => { setCursor(bounds.end); setPlaying(false); }} ariaLabel="Skip to end"><SkipForward className="h-4 w-4" /> End</Button>
          <div className="flex border border-line bg-panel-2 p-0.5" role="group" aria-label="Playback speed">
            {SPEEDS.map((s) => (
              <button key={s} type="button" onClick={() => setSpeed(s)} aria-pressed={speed === s}
                className={clsx("px-2 py-1 font-mono text-xs", speed === s ? "bg-accent text-bg" : "text-muted hover:text-ink")}>
                {s}×
              </button>
            ))}
          </div>
        </>}>
        {data.summary}
      </PageHeader>

      <Card className="mb-4" scanlines title={<span className="font-mono text-cyan">{fmtTime(now, true)}</span>}
        subtitle={`${visible.length} of ${data.events.length} events replayed · space bar plays and pauses`}>
        <KillChain scores={scores} now={now} bounds={bounds} selected={selected} onSelect={setSelected} />
        <input type="range" min={bounds.start} max={bounds.end} step={1000} value={now} aria-label="Scenario time"
          onChange={(e) => { setPlaying(false); setCursor(Number(e.target.value)); }}
          className="mt-3 w-full accent-[var(--ae-cyan)]" />
        <div className="mt-1 h-1 overflow-hidden rounded bg-panel-2"><div className="h-full bg-accent" style={{ width: `${pct}%` }} /></div>
      </Card>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Kpi label="Stages detected" value={`${board.detected}/${board.total}`} tone={board.pct >= 75 ? "good" : "warn"} hint={`${board.pct}% detection coverage`} />
        <Kpi label="Telemetry only" value={board.telemetryOnly} tone={board.telemetryOnly ? "warn" : "default"} hint="seen, but no alert" />
        <Kpi label="Missed" value={board.missed} tone={board.missed && finished ? "bad" : "default"} hint={finished ? "no data at all" : "or not reached yet"} />
        <Kpi label="Mean time to detect" value={fmtDuration(board.meanTtdS)} hint="stage start → first finding" />
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-5">
        <Card className="xl:col-span-3" title="Event feed" subtitle="Newest first. Findings are highlighted.">
          <ul className="max-h-[420px] divide-y divide-line overflow-y-auto" aria-live="polite">
            {feed.map((e) => <FeedRow key={e.uid} e={e} />)}
            {!feed.length && <li className="py-6 text-center text-sm text-muted">Press play to start the attack.</li>}
          </ul>
        </Card>
        <Card className="xl:col-span-2" title={focus ? `Stage: ${focus.name}` : "Stage scoreboard"}
          subtitle={focus ? "Click the stage again to go back to the list." : "Click a stage for details."}>
          {focus ? <StageDetail s={focus} /> : (
            <ul className="space-y-2">
              {scores.map((s) => (
                <li key={s.stage}>
                  <button type="button" onClick={() => setSelected(s.stage)}
                    className="flex w-full items-center gap-2 px-2 py-1.5 text-left text-sm hover:bg-panel-2">
                    <span className="flex-1 truncate">{s.name}</span>
                    <span className="font-mono text-[11px] text-muted">{s.techniques.join(", ")}</span>
                    {now >= s.start ? <OutcomeChip outcome={s.outcome} /> : <Tag>pending</Tag>}
                  </button>
                </li>
              ))}
            </ul>
          )}
          {finished && <GapHints scores={scores} />}
        </Card>
      </div>
    </>
  );
}

function KillChain({ scores, now, bounds, selected, onSelect }: {
  scores: StageScore[]; now: number; bounds: { start: number; end: number }; selected: string | null; onSelect: (id: string | null) => void;
}) {
  return (
    <ol className="grid gap-2" style={{ gridTemplateColumns: `repeat(${scores.length}, minmax(0, 1fr))` }} aria-label="Kill chain">
      {scores.map((s, i) => {
        const reached = now >= s.start;
        const tone = !reached ? "border-line text-muted" : s.outcome === "detected" ? "border-good bg-good/10 text-good"
          : s.outcome === "telemetry_only" ? "border-warn bg-warn/10 text-warn" : "border-bad bg-bad/10 text-bad";
        return (
          <li key={s.stage}>
            <button type="button" onClick={() => onSelect(selected === s.stage ? null : s.stage)}
              title={`${s.tactic}: ${s.name} (${fmtTime(s.start)})`}
              className={clsx("ae-in h-full w-full border px-2 py-2 text-left transition", tone,
                selected === s.stage && "ring-2 ring-accent", reached && s.outcome === "detected" && "wf-live")}>
              <div className="text-[10px] uppercase tracking-wider opacity-80">{i + 1} · {s.tactic}</div>
              <div className="mt-0.5 truncate text-xs font-semibold text-ink">{s.name}</div>
              <div className="mt-0.5 font-mono text-[10px]">
                {!reached ? `T+${fmtDuration((s.start - bounds.start) / 1000)}` : s.ttd_ms !== null ? `TTD ${fmtDuration(s.ttd_ms / 1000)}` : s.outcome === "telemetry_only" ? `${s.telemetry_events} events, no alert` : "no data"}
              </div>
            </button>
          </li>
        );
      })}
    </ol>
  );
}

function FeedRow({ e }: { e: Row }) {
  const finding = e.class_uid === 2004 || e.class_uid === 2005;
  return (
    <li className={clsx("wf-in flex items-start gap-3 py-1.5 text-sm", finding && "rounded bg-bad/5")}>
      <span className="w-20 shrink-0 pt-0.5 font-mono text-xs text-muted">{fmtTime(e.time)}</span>
      {finding ? <Severity id={e.severity_id} /> : <span className="w-24 shrink-0 text-[11px] text-muted">{CLASS_NAMES[e.class_uid] ?? e.class_uid}</span>}
      <span className="min-w-0 flex-1">
        <span className={clsx("block truncate", finding && "font-medium")}>{e.finding_title ?? e.message ?? e.cmd_line ?? e.file_path ?? "event"}</span>
        <span className="block truncate font-mono text-[11px] text-muted">
          {[e.hostname, e.user_name, e.src_ip, e.process_name].filter(Boolean).join(" · ")}
        </span>
      </span>
      {e.techniques.length > 0 && <span className="hidden font-mono text-[11px] text-accent md:inline">{e.techniques.join(" ")}</span>}
      <Tag>{e.product ?? "?"}</Tag>
    </li>
  );
}

function StageDetail({ s }: { s: StageScore }) {
  return (
    <div className="space-y-3 text-sm">
      <div className="flex items-center gap-2"><OutcomeChip outcome={s.outcome} /><Tag mono>{s.techniques.join(", ")}</Tag><Tag>{s.tactic}</Tag></div>
      <dl className="grid grid-cols-2 gap-2">
        <div><dt className="text-[11px] text-muted">Stage start</dt><dd className="font-mono">{fmtTime(s.start)}</dd></div>
        <div><dt className="text-[11px] text-muted">Time to detect</dt><dd className="font-mono">{s.ttd_ms === null ? "n/a" : fmtDuration(s.ttd_ms / 1000)}</dd></div>
        <div><dt className="text-[11px] text-muted">Telemetry events</dt><dd className="font-mono">{s.telemetry_events}</dd></div>
        <div><dt className="text-[11px] text-muted">Matching findings</dt><dd className="font-mono">{s.findings.length}</dd></div>
      </dl>
      <ul className="space-y-1">
        {s.findings.map((f) => (
          <li key={f.uid} className="flex gap-2 text-xs"><span className="font-mono text-muted">{fmtTime(f.time)}</span><span className="flex-1">{f.title}</span><Tag>{f.product}</Tag></li>
        ))}
      </ul>
    </div>
  );
}

function GapHints({ scores }: { scores: StageScore[] }) {
  const gaps = scores.filter((s) => s.outcome !== "detected");
  if (!gaps.length) return <p className="mt-4 bg-good/10 p-3 text-sm text-good">Every stage was detected.</p>;
  return (
    <div className="mt-4 border border-warn/40 bg-warn/5 p-3">
      <div className="mb-1 flex items-center gap-1.5 text-sm font-semibold text-warn"><Lightbulb className="h-4 w-4" /> Detection gaps to close</div>
      <ul className="space-y-1 text-xs text-muted">
        {gaps.map((g) => (
          <li key={g.stage}>
            <span className="font-medium text-ink">{g.name}</span> ({g.techniques.join(", ")}):{" "}
            {g.outcome === "telemetry_only"
              ? `the platform saw ${g.telemetry_events} events but no rule fired. A Sigma rule in 08 can turn this telemetry into a finding.`
              : "no telemetry at all. A new sensor or log source is needed before any rule can help."}
          </li>
        ))}
      </ul>
      <Link to="/rules" className="mt-2 inline-block text-xs text-accent hover:underline">See the rules that close these gaps →</Link>
    </div>
  );
}
