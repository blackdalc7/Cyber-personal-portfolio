import { GhostAnnotation, cn } from "@portfolio/aegis-ui";
import { useState } from "react";
import { Link } from "react-router-dom";
import { Card, Empty, ErrorBox, Loading, PageHeader, Tag } from "../components/ui";
import { useLoad } from "../lib/data";

/**
 * The analyst is an engine, not a chatbot: this page shows what it did (a tool-call trace, like strace) and what it
 * concluded (inline annotations). Its conclusions also appear inline on each incident page.
 */
export default function Analyst() {
  const analyses = useLoad((s) => s.analyses());
  const [idx, setIdx] = useState(0);
  if (analyses.error) return <ErrorBox error={analyses.error} />;
  if (!analyses.data) return <Loading label="Loading investigations" />;
  if (!analyses.data.length) {
    return (
      <>
        <PageHeader title="Analyst engine" kicker="AI-assisted triage" />
        <Empty quipKey="analyst">No investigations yet. Run 10-ai-analyst-mcp against an incident and point WF_ANALYST_DIR at its output.</Empty>
      </>
    );
  }
  const a = analyses.data[Math.min(idx, analyses.data.length - 1)];

  return (
    <>
      <PageHeader title="Analyst engine" kicker="AI-assisted triage">
        Reads the lake and the asset inventory through read-only MCP tools, quotes a tool result for every claim, and
        writes its verdict as an annotation on the incident. It can suggest containment; it can never perform it.
      </PageHeader>
      <div className="grid gap-4 xl:grid-cols-4">
        <Card title="Investigations">
          <ul className="space-y-1">
            {analyses.data.map((x, i) => (
              <li key={`${x.incident_id}-${i}`}>
                <button type="button" onClick={() => setIdx(i)}
                  className={cn("w-full border px-2 py-1.5 text-left font-mono text-xs", i === idx ? "border-ink bg-ink text-bg" : "border-transparent text-ink hover:border-line")}>
                  <div>{x.incident_id}</div>
                  <div className={cn("text-[11px]", i === idx ? "text-bg/80" : "text-muted")}>{x.provider} · {x.model} · {x.tool_calls.length} calls</div>
                </button>
              </li>
            ))}
          </ul>
        </Card>
        <div className="space-y-10 xl:col-span-3">
          <Card title={<>Annotation on <Link className="text-accent hover:underline" to={`/incidents/${encodeURIComponent(a.incident_id)}`}>{a.incident_id}</Link></>}
            actions={<div className="flex gap-1.5"><Tag mono>{a.verdict}</Tag><Tag mono>{Math.round(a.confidence * 100)}%</Tag></div>}>
            <GhostAnnotation source={`AI analyst · ${a.provider}`} confidence={a.confidence} verified={a.citations_valid}
              text={a.summary} citations={a.evidence.map((e) => ({ ref: e.tool_call, quote: e.quote }))}>
              <div className="mt-3 text-[13px] text-muted">
                <div className="ae-label mb-1">Suggested next steps, for a human to approve in project 02</div>
                <ol className="list-decimal space-y-0.5 pl-5">{a.recommended_actions.map((r) => <li key={r}>{r}</li>)}</ol>
              </div>
            </GhostAnnotation>
          </Card>
          <Card title={`Engine trace · ${a.tool_calls.length} read-only calls`} subtitle="Arguments are schema-validated; every query is parameterised and row-limited.">
            <ol className="max-h-[520px] space-y-3 overflow-y-auto bg-panel-2 p-4 font-mono text-[12px] leading-relaxed">
              {a.tool_calls.map((t) => (
                <li key={t.id}>
                  <div><span className="text-muted">[{t.id}]</span> <span className="text-accent">{t.tool}</span><span className="text-muted">({JSON.stringify(t.arguments)})</span></div>
                  <div className="whitespace-pre-wrap pl-4 text-muted">= {t.result_preview}</div>
                  {a.evidence.some((e) => e.tool_call === t.id) && (
                    <div className="pl-4 text-warn">Cited in the verdict: “{a.evidence.find((e) => e.tool_call === t.id)?.quote}”</div>
                  )}
                </li>
              ))}
              <li className="border-t border-line pt-2 text-muted">Finished with verdict <span className="text-ink">{a.verdict}</span></li>
            </ol>
          </Card>
        </div>
      </div>
    </>
  );
}
