import { GhostAnnotation, TextScramble, cn } from "@portfolio/aegis-ui";
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
  if (!analyses.data) return <Loading label="warming up the analyst engine" />;
  if (!analyses.data.length) {
    return (
      <>
        <PageHeader title="Analyst engine" kicker="ai" />
        <Empty quipKey="analyst">No investigations yet. Run 10-ai-analyst-mcp against an incident and point WF_ANALYST_DIR at its output.</Empty>
      </>
    );
  }
  const a = analyses.data[Math.min(idx, analyses.data.length - 1)];

  return (
    <>
      <PageHeader title="Analyst engine" kicker="ai">
        Reads the lake and the asset inventory through read-only MCP tools, quotes a tool result for every claim, and
        writes its verdict as an annotation on the incident. It can suggest containment; it can never perform it.
      </PageHeader>
      <div className="grid gap-4 xl:grid-cols-4">
        <Card title="Investigations">
          <ul className="space-y-1">
            {analyses.data.map((x, i) => (
              <li key={`${x.incident_id}-${i}`}>
                <button type="button" onClick={() => setIdx(i)}
                  className={cn("w-full border px-2 py-1.5 text-left font-mono text-xs", i === idx ? "border-cyan/50 bg-cyan/10 text-cyan" : "border-transparent text-ink/80 hover:border-line")}>
                  <div>{x.incident_id}</div>
                  <div className="text-[10px] text-muted">{x.provider} · {x.model} · {x.tool_calls.length} calls</div>
                </button>
              </li>
            ))}
          </ul>
        </Card>
        <div className="space-y-4 xl:col-span-3">
          <Card title={<>Annotation on <Link className="text-cyan hover:underline" to={`/incidents/${encodeURIComponent(a.incident_id)}`}>{a.incident_id}</Link></>}
            actions={<div className="flex gap-1.5"><Tag mono>{a.verdict}</Tag><Tag mono>{Math.round(a.confidence * 100)}%</Tag></div>}>
            <GhostAnnotation source={`AI analyst · ${a.provider}`} confidence={a.confidence} verified={a.citations_valid}
              text={a.summary} citations={a.evidence.map((e) => ({ ref: e.tool_call, quote: e.quote }))}>
              <p className="mt-2 font-mono text-[11px] text-muted">suggests (for a human to approve in 02): {a.recommended_actions.join(" · ")}</p>
            </GhostAnnotation>
          </Card>
          <Card scanlines title={`Engine trace · ${a.tool_calls.length} read-only calls`} subtitle="Arguments are schema-validated; every query is parameterised and row-limited.">
            <ol className="max-h-[520px] space-y-3 overflow-y-auto bg-black/30 p-3 font-mono text-[11.5px] leading-relaxed">
              {a.tool_calls.map((t, i) => (
                <li key={t.id} className="ae-in" style={{ animationDelay: `${i * 60}ms` }}>
                  <div><span className="text-muted">[{t.id}]</span> <span className="text-cyan">{t.tool}</span><span className="text-ink/70">({JSON.stringify(t.arguments)})</span></div>
                  <TextScramble as="div" duration={400} className="whitespace-pre-wrap pl-4 text-green/80" text={`= ${t.result_preview}`} />
                  {a.evidence.some((e) => e.tool_call === t.id) && (
                    <div className="pl-4 text-amber">↳ cited: “{a.evidence.find((e) => e.tool_call === t.id)?.quote}”</div>
                  )}
                </li>
              ))}
              <li className="text-muted">+++ exited with verdict <span className="text-ink">{a.verdict}</span> +++<span className="ae-caret" /></li>
            </ol>
          </Card>
        </div>
      </div>
    </>
  );
}
