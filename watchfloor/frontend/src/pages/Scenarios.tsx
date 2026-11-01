import { PlayCircle } from "lucide-react";
import { Link } from "react-router-dom";
import { Card, ErrorBox, Loading, PageHeader, Tag, actionLinkClass } from "../components/ui";
import { useLoad } from "../lib/data";

export default function Scenarios() {
  const scenarios = useLoad((s) => s.scenarios());
  if (scenarios.error) return <ErrorBox error={scenarios.error} />;
  if (!scenarios.data) return <Loading />;
  return (
    <>
      <PageHeader title="Attack scenarios">
        Each scenario is a recorded attack, stage by stage. Press play and watch whether the platform detects it, stage
        by stage. The scoreboard is computed from the events as they arrive, the same way the hub scores a live run.
      </PageHeader>
      <div className="grid gap-x-10 gap-y-10 lg:grid-cols-2">
        {scenarios.data.map((sc) => (
          <Card key={sc.id} title={sc.title} subtitle={`${sc.stages.length} stages · ${sc.hosts.join(", ")}`}
            actions={<Link to={`/scenarios/${sc.id}`} aria-label={`Play ${sc.title}`}
              className={actionLinkClass}>
              <PlayCircle className="h-4 w-4" aria-hidden="true" /> Play</Link>}>
            <p className="text-sm text-muted">{sc.summary}</p>
            <ol className="mt-3 flex flex-wrap gap-1.5">
              {sc.stages.map((st, i) => (
                <li key={st.id}><Tag>{i + 1}. {st.name}</Tag></li>
              ))}
            </ol>
            <p className="mt-4 text-[12px] text-muted"><span className="font-medium text-ink">Provenance:</span> {sc.provenance}</p>
            {sc.simulated_parts.length > 0 && (
              <p className="mt-1 text-[12px] text-warn"><span className="font-medium">Simulated:</span> {sc.simulated_parts.join("; ")}</p>
            )}
          </Card>
        ))}
      </div>
    </>
  );
}
