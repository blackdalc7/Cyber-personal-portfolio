import clsx from "clsx";
import { CheckCircle2, XCircle } from "lucide-react";
import { useMemo, useState } from "react";
import type { RuleInfo } from "../api/types";
import { Card, Empty, ErrorBox, Kpi, Loading, PageHeader, Tag } from "../components/ui";
import { useLoad } from "../lib/data";

export default function Rules() {
  const rules = useLoad((s) => s.rules());
  const [sel, setSel] = useState<RuleInfo | null>(null);
  const list = useMemo(() => rules.data?.rules ?? [], [rules.data]);
  if (rules.error) return <ErrorBox error={rules.error} />;
  if (!rules.data) return <Loading />;
  if (!list.length) {
    return (
      <>
        <PageHeader title="Detection rules" kicker="detect" />
        <Empty quipKey="rules">No rules index. Run 08-detection-rules' build and point WF_RULES_INDEX at rules_index.json.</Empty>
      </>
    );
  }

  const tests = list.flatMap((r) => r.tests);
  const passed = tests.filter((t) => t.passed).length;
  const techniques = new Set(list.flatMap((r) => r.techniques));
  const cur = sel ?? list[0];

  return (
    <>
      <PageHeader title="Detection rules">
        Sigma rules from 08, written against OCSF fields and compiled to DuckDB SQL. Every rule ships with a sample that
        must match and one that must not; CI runs both on every change.
      </PageHeader>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Kpi label="Rules" value={list.length} />
        <Kpi label="Techniques covered" value={techniques.size} />
        <Kpi label="Tests passing" value={`${passed}/${tests.length}`} tone={passed === tests.length ? "good" : "bad"} />
        <Kpi label="Tuned rules" value={list.filter((r) => r.tuned_from).length} hint="with a recorded false-positive fix" />
      </div>
      <div className="mt-4 grid gap-4 xl:grid-cols-5">
        <Card className="xl:col-span-2" title="Rules">
          <ul className="divide-y divide-line">
            {list.map((r) => {
              const ok = r.tests.every((t) => t.passed);
              return (
                <li key={r.id}>
                  <button type="button" onClick={() => setSel(r)} className={clsx("flex w-full items-center gap-2 px-1 py-2 text-left text-sm hover:bg-panel-2", cur.id === r.id && "bg-accent/5")}>
                    {ok ? <CheckCircle2 className="h-4 w-4 shrink-0 text-good" aria-label="tests pass" /> : <XCircle className="h-4 w-4 shrink-0 text-bad" aria-label="tests fail" />}
                    <span className="flex-1 truncate">{r.title}</span>
                    <Tag>{r.level}</Tag>
                  </button>
                </li>
              );
            })}
          </ul>
        </Card>
        <Card className="xl:col-span-3" title={cur.title} subtitle={<span className="font-mono">{cur.path}</span>}>
          <div className="flex flex-wrap gap-1.5">{cur.techniques.map((t) => <Tag key={t} mono>{t}</Tag>)}<Tag>{cur.status}</Tag><Tag>{cur.logsource}</Tag></div>
          {cur.description && <p className="mt-3 text-sm text-muted">{cur.description}</p>}
          {cur.tuned_from && <p className="mt-2 bg-warn/10 p-2 text-xs text-warn">Tuning note: {cur.tuned_from}</p>}
          <h3 className="mt-4 text-xs font-semibold uppercase tracking-wider text-muted">Tests</h3>
          <ul className="mt-1 space-y-1 text-sm">
            {cur.tests.map((t) => (
              <li key={t.name} className="flex items-center gap-2">
                {t.passed ? <CheckCircle2 className="h-3.5 w-3.5 text-good" /> : <XCircle className="h-3.5 w-3.5 text-bad" />}
                <span className="flex-1 font-mono text-xs">{t.name}</span><span className="font-mono text-xs text-muted">expected {t.expected}, got {t.got}</span>
              </li>
            ))}
          </ul>
          {cur.queries?.duckdb && (
            <>
              <h3 className="mt-4 text-xs font-semibold uppercase tracking-wider text-muted">Compiled DuckDB SQL</h3>
              <pre className="mt-1 max-h-64 overflow-auto bg-panel-2 p-3 font-mono text-[11px] leading-relaxed">{cur.queries.duckdb}</pre>
            </>
          )}
        </Card>
      </div>
    </>
  );
}
