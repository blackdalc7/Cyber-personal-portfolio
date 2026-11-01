import { GhostAnnotation, HexCascade, ISOLATION_QUIPS, SlideToExecute, TextScramble, Topology } from "@portfolio/aegis-ui";
import clsx from "clsx";
import { Check, ChevronLeft, FileArchive, ShieldCheck } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import type { IncidentDetail as Detail, TreeNode } from "../api/types";
import { Card, Empty, ErrorBox, Kpi, Loading, PageHeader, Severity, Tag } from "../components/ui";
import { useLoad, useSource } from "../lib/data";
import { fmtDuration, fmtTime } from "../lib/logic";
import { StatusPill } from "./Incidents";

const STEPS = [
  { key: "detected", label: "Detected" },
  { key: "opened", label: "Incident opened" },
  { key: "decided", label: "Human decision" },
  { key: "contained", label: "Contained" },
];

export default function IncidentDetail() {
  const { id = "" } = useParams();
  const detail = useLoad((s) => s.incident(id), [id]);
  if (detail.error) return <ErrorBox error={detail.error} />;
  if (!detail.data) return <Loading />;
  const d = detail.data;
  const inc = d.incident;
  return (
    <>
      <Link to="/incidents" className="mb-2 inline-flex items-center gap-1 text-xs text-muted hover:text-ink"><ChevronLeft className="h-3.5 w-3.5" /> All incidents</Link>
      <PageHeader title={`${inc.id}: ${inc.title}`} actions={<><Severity id={inc.severity_id} /><StatusPill status={inc.status} /></>}>
        {inc.description}
      </PageHeader>

      {d.analyses.slice(0, 1).map((a) => (
        <GhostAnnotation key={`${a.model}-${a.created}`} className="mb-4" source={`AI analyst · ${a.provider}`} confidence={a.confidence}
          verified={a.citations_valid} text={`${a.verdict.replace(/_/g, " ")}: ${a.summary}`}
          citations={a.evidence.map((e) => ({ ref: e.tool_call, quote: e.quote }))}>
          {a.recommended_actions.length > 0 && (
            <p className="mt-1 font-mono text-[11px] text-muted">suggests: {a.recommended_actions.join(" · ")}</p>
          )}
        </GhostAnnotation>
      ))}

      <ResponseStepper d={d} />

      <div className="mt-4 grid grid-cols-2 gap-3 md:grid-cols-4">
        <Kpi label="Host" value={<span className="text-lg">{inc.host ?? "n/a"}</span>} />
        <Kpi label="Indicator" value={<span className="text-lg">{inc.indicator_ip ?? "n/a"}</span>} />
        <Kpi label="Time to approve" value={fmtDuration(inc.tta_s)} hint={inc.decided_by ? `by ${inc.decided_by}` : "awaiting"} />
        <Kpi label="Time to contain" value={fmtDuration(inc.ttr_s)} tone={inc.ttr_s !== null ? "good" : "warn"} />
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-2">
        {d.chain && (
          <Card title="Correlated chain" subtitle={d.chain.attack_stage ? `Stage: ${d.chain.attack_stage}` : undefined}
            actions={d.chain.verdict ? <Tag>{d.chain.verdict}</Tag> : undefined}>
            <TextScramble as="p" className="text-sm" text={d.chain.summary ?? ""} />
            {!!d.chain.rule_ids?.length && <div className="mt-2 flex flex-wrap gap-1">{d.chain.rule_ids.map((r) => <Tag key={r} mono>{r}</Tag>)}</div>}
            {!!d.chain.recommended_actions?.length && (
              <ul className="mt-3 list-disc space-y-1 pl-5 text-sm text-muted">{d.chain.recommended_actions.map((a) => <li key={a}>{a}</li>)}</ul>
            )}
          </Card>
        )}
        {d.auth_summary.length > 0 && (
          <Card title="Authentication summary" subtitle="Grouped by outcome, source and account">
            <table className="w-full text-sm">
              <thead className="text-left text-[11px] uppercase text-muted"><tr><th className="py-1">Outcome</th><th>Source</th><th>Account</th><th className="text-right">Count</th><th className="text-right">Window</th></tr></thead>
              <tbody className="divide-y divide-line">
                {d.auth_summary.map((a, i) => (
                  <tr key={i}>
                    <td className={clsx("py-1.5", a.status_id === 1 ? "text-good" : "text-bad")}>{a.status_id === 1 ? "success" : "failure"}</td>
                    <td className="font-mono text-xs">{a.src_ip}</td><td className="font-mono text-xs">{a.user_name}</td>
                    <td className="text-right font-mono">{a.n}</td><td className="text-right font-mono text-xs">{fmtDuration((a.last - a.first) / 1000)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        )}
      </div>

      {d.process_tree && d.process_tree.nodes.length > 0 && <ProcessTreeCard tree={d.process_tree} />}

      <div className="mt-4 grid gap-4 xl:grid-cols-5">
        <Card className="xl:col-span-3" title="Timeline" subtitle="Findings, activity and response actions in one sequence">
          <ol className="relative max-h-[460px] space-y-2 overflow-y-auto border-l border-line pl-4">
            {d.timeline.map((t, i) => (
              <li key={`${t.time}-${i}`} className="relative">
                <span className={clsx("absolute -left-[21px] top-1.5 h-2.5 w-2.5 rounded-full",
                  t.kind === "finding" ? "bg-bad" : t.kind === "response" ? "bg-accent" : "bg-muted")} />
                <div className="flex items-start gap-2 text-sm">
                  <span className="w-20 shrink-0 font-mono text-xs text-muted">{fmtTime(t.time)}</span>
                  <span className="flex-1">{t.title}{t.actor && <span className="text-muted"> · {t.actor}</span>}</span>
                  {t.product && <Tag>{t.product}</Tag>}
                </div>
              </li>
            ))}
          </ol>
        </Card>
        <div className="space-y-4 xl:col-span-2">
          <EvidenceCard d={d} />
        </div>
      </div>

      <Card className="mt-4" title={`Findings (${d.findings.length})`}>
        <ul className="divide-y divide-line">
          {d.findings.map((f) => (
            <li key={f.uid} className="flex items-center gap-3 py-1.5 text-sm">
              <span className="w-20 font-mono text-xs text-muted">{fmtTime(f.time)}</span><Severity id={f.severity_id} />
              <span className="flex-1 truncate">{f.finding_title}</span>
              <span className="font-mono text-[11px] text-accent">{f.techniques.join(" ")}</span><Tag>{f.product}</Tag>
            </li>
          ))}
        </ul>
        {!d.findings.length && <Empty>No findings are linked to this incident.</Empty>}
      </Card>
    </>
  );
}

function ResponseStepper({ d }: { d: Detail }) {
  const inc = d.incident;
  const firstFinding = d.findings.length ? Math.min(...d.findings.map((f) => f.time)) : null;
  const at: Record<string, number | null> = {
    detected: firstFinding,
    opened: inc.time,
    decided: inc.tta_s !== null && firstFinding !== null ? firstFinding + inc.tta_s * 1000 : null,
    contained: inc.ttr_s !== null && firstFinding !== null ? firstFinding + inc.ttr_s * 1000 : null,
  };
  return (
    <Card>
      <ol className="grid grid-cols-2 gap-3 md:grid-cols-4" aria-label="Response progress">
        {STEPS.map((s, i) => {
          const done = at[s.key] !== null;
          return (
            <li key={s.key} className="flex items-center gap-3">
              <span className={clsx("flex h-8 w-8 shrink-0 items-center justify-center rounded-full border-2 text-xs font-semibold",
                done ? "border-good bg-good/15 text-good" : "border-line text-muted")}>{done ? <Check className="h-4 w-4" /> : i + 1}</span>
              <div>
                <div className="text-sm font-medium">{s.label}</div>
                <div className="font-mono text-[11px] text-muted">{done ? fmtTime(at[s.key] as number) : "pending"}</div>
              </div>
            </li>
          );
        })}
      </ol>
      <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-line pt-3">
        <p className="flex max-w-xl items-center gap-1.5 text-[11px] text-muted"><ShieldCheck className="h-3.5 w-3.5 shrink-0" />
          Approve and reject live in Slack or Discord and are verified by 02. Sliding only asks 02 to post an approval card.</p>
        {inc.host && <IsolationRequest host={inc.host} incidentId={inc.id} contained={inc.ttr_s !== null} />}
      </div>
    </Card>
  );
}

function IsolationRequest({ host, incidentId, contained }: { host: string; incidentId: string; contained: boolean }) {
  const src = useSource();
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <div className="flex flex-col items-end gap-1">
      {busy ? <div className="w-72"><HexCascade rows={3} label={ISOLATION_QUIPS[0]} /></div> : (
        <SlideToExecute label={`Slide to isolate ${host}`} className="w-80" disabled={contained} doneLabel="approval requested"
          disabledReason="Already contained. Isolating it twice will not make it more isolated."
          onExecute={async () => {
            setBusy(true);
            try {
              const r = await src.requestIsolation(host, "requested from the incident page", incidentId);
              setMsg(r.status === "simulated"
                ? { ok: true, text: "Replay demo: simulated. In live mode an approval card would now be waiting in Slack." }
                : { ok: true, text: `Approval requested (${r.soar?.incident_id ?? "incident"}). Now find an approver who is not you.` });
            } catch (e) {
              setMsg({ ok: false, text: e instanceof Error ? e.message : String(e) });
            } finally {
              setBusy(false);
            }
          }} />
      )}
      {msg && <p role="status" className={clsx("font-mono text-[11px]", msg.ok ? "text-green" : "text-crimson")}>{msg.text}</p>}
    </div>
  );
}

function ProcessTreeCard({ tree }: { tree: { host: string; nodes: TreeNode[]; edges: { source: string; target: string }[] } }) {
  const nodes = useMemo(() => tree.nodes.map((n) => ({ id: n.id, label: `${n.name} (${n.pid})`, flagged: n.alerts.length > 0 })), [tree]);
  const roots = useMemo(() => tree.nodes.filter((n) => !tree.edges.some((e) => e.target === n.id)).map((n) => n.id), [tree]);
  return (
    <Card className="mt-4" scanlines title={`Process tree · ${tree.host}`} subtitle="Red nodes raised a finding. Drag to untangle, click for the command line.">
      <Topology nodes={nodes} edges={tree.edges} roots={roots} ariaLabel="Process tree" height={360}
        renderContext={(id) => {
          const node = tree.nodes.find((n) => n.id === id);
          if (!node) return null;
          return (
            <dl className="space-y-2">
              <div><dt className="font-mono text-[10px] uppercase tracking-widest text-muted">process</dt><dd className="font-mono">{node.name} · pid {node.pid}</dd></div>
              <div><dt className="font-mono text-[10px] uppercase tracking-widest text-muted">started</dt><dd className="font-mono text-xs">{fmtTime(node.time, true)}</dd></div>
              <div><dt className="font-mono text-[10px] uppercase tracking-widest text-muted">cmdline</dt>
                <dd className="max-h-28 overflow-y-auto break-all border border-line bg-black/40 p-2 font-mono text-[11px] text-green">{node.cmd_line ?? "n/a"}</dd></div>
              {node.alerts.length > 0 && <div><dt className="font-mono text-[10px] uppercase tracking-widest text-crimson">findings</dt>
                <dd><ul className="list-disc pl-4 text-xs">{node.alerts.map((a) => <li key={a}>{a}</li>)}</ul></dd></div>}
            </dl>
          );
        }} />
    </Card>
  );
}

function EvidenceCard({ d }: { d: Detail }) {
  return (
    <Card title="Evidence packages (09)" actions={<FileArchive className="h-4 w-4 text-muted" />}>
      {d.evidence.length ? d.evidence.map((e) => (
        <div key={`${e.incident_id}-${e.created}`} className="text-sm">
          <div className="flex flex-wrap items-center gap-1.5"><span className="font-mono text-xs">{e.created}</span>{e.sources.map((s) => <Tag key={s}>{s}</Tag>)}{e.simulated && <Tag>simulated</Tag>}</div>
          <ul className="mt-2 space-y-0.5 font-mono text-[11px] text-muted">
            {e.files.map((f) => <li key={f.name} className="truncate" title={f.sha256}>{f.name} · sha256 {f.sha256.slice(0, 12)}…</li>)}
          </ul>
          {!!e.highlights?.length && (
            <ul className="mt-2 space-y-1 text-xs">{e.highlights.slice(0, 6).map((h, i) => <li key={i}><span className="font-mono text-muted">{h.time.slice(11, 19)}</span> {h.title} <Tag>{h.source}</Tag></li>)}</ul>
          )}
        </div>
      )) : <Empty>No evidence collected yet. Approving containment triggers a Velociraptor and Hayabusa collection.</Empty>}
    </Card>
  );
}
