import { PlayCircle } from "lucide-react";
import { Link } from "react-router-dom";
import { Card, ErrorBox, Loading, PageHeader, Tag } from "../components/ui";
import { useLoad } from "../lib/data";

export default function Scenarios() {
  const scenarios = useLoad((s) => s.scenarios());
  if (scenarios.error) return <ErrorBox error={scenarios.error} />;
  if (!scenarios.data) return <Loading />;
  return (
    <>
      <PageHeader title="Attack scenarios">
        Each scenario is a recorded attack, stage by stage. Press play and watch the platform detect it (or not) in
        real time. The scoreboard is computed from the events as they arrive, the same way the hub scores a live run.
      </PageHeader>
      <div className="grid gap-4 lg:grid-cols-2">
        {scenarios.data.map((sc) => (
          <Card key={sc.id} title={sc.title} subtitle={`${sc.stages.length} stages · ${sc.hosts.join(", ")}`}
            actions={<Link to={`/scenarios/${sc.id}`} aria-label={`Play ${sc.title}`}
              className="inline-flex items-center gap-1.5 border border-cyan bg-cyan/10 px-3 py-1.5 font-mono text-xs uppercase tracking-wider text-cyan hover:bg-cyan/20">
              <PlayCircle className="h-4 w-4" /> Play</Link>}>
            <p className="text-sm text-muted">{sc.summary}</p>
            <ol className="mt-3 flex flex-wrap gap-1.5">
              {sc.stages.map((st, i) => (
                <li key={st.id}><Tag>{i + 1}. {st.name}</Tag></li>
              ))}
            </ol>
            <p className="mt-3 text-[11px] text-muted"><span className="font-semibold">Provenance:</span> {sc.provenance}</p>
            {sc.simulated_parts.length > 0 && (
              <p className="mt-1 text-[11px] text-warn"><span className="font-semibold">Simulated:</span> {sc.simulated_parts.join("; ")}</p>
            )}
          </Card>
        ))}
      </div>
    </>
  );
}
