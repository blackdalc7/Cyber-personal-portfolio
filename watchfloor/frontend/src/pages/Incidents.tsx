import clsx from "clsx";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Card, Empty, ErrorBox, Loading, PageHeader, Severity, Tag } from "../components/ui";
import { useLoad } from "../lib/data";
import { fmtDuration, fmtTime } from "../lib/logic";

const STATUS_TONE: Record<string, string> = {
  contained: "bg-good/15 text-good",
  remediated: "bg-good/15 text-good",
  resolved: "bg-good/15 text-good",
  awaiting_approval: "bg-warn/15 text-warn",
  open: "bg-bad/15 text-bad",
  rejected: "bg-panel-2 text-muted",
  expired: "bg-panel-2 text-muted",
  failed: "bg-crit/15 text-crit",
};

export function StatusPill({ status }: { status: string }) {
  return <span className={clsx("rounded-full px-2 py-0.5 text-[11px] font-semibold", STATUS_TONE[status] ?? "bg-panel-2 text-muted")}>{status.replace(/_/g, " ")}</span>;
}

export default function Incidents() {
  const incidents = useLoad((s) => s.incidents());
  const [q, setQ] = useState("");
  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (incidents.data ?? []).filter((i) => !needle || `${i.id} ${i.title} ${i.host} ${i.indicator_ip} ${i.status}`.toLowerCase().includes(needle));
  }, [incidents.data, q]);

  if (incidents.error) return <ErrorBox error={incidents.error} />;
  if (!incidents.data) return <Loading />;
  return (
    <>
      <PageHeader title="Incidents">
        Incidents are opened by the SOAR bot (project 02) when a finding crosses its severity threshold. Containment
        only runs after a signed human approval in Slack or Discord; this page shows the record, it never approves.
      </PageHeader>
      <Card>
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter by id, host, IP or status" aria-label="Filter incidents"
          className="mb-3 w-full border border-line bg-panel-2 px-3 py-1.5 text-sm outline-none focus:border-accent md:w-80" />
        {rows.length ? (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-left text-[11px] uppercase tracking-wider text-muted">
                <tr><th className="py-2 pr-3">Incident</th><th className="pr-3">Severity</th><th className="pr-3">Status</th><th className="pr-3">Host</th><th className="pr-3">Indicator</th><th className="pr-3">Opened</th><th className="pr-3">Approve</th><th>Contain</th></tr>
              </thead>
              <tbody className="divide-y divide-line">
                {rows.map((i) => (
                  <tr key={i.id} className="hover:bg-panel-2/60">
                    <td className="py-2 pr-3">
                      <Link to={`/incidents/${encodeURIComponent(i.id)}`} className="font-medium text-accent hover:underline">{i.id}</Link>
                      <div className="max-w-md truncate text-xs text-muted">{i.title}</div>
                    </td>
                    <td className="pr-3"><Severity id={i.severity_id} /></td>
                    <td className="pr-3"><StatusPill status={i.status} /></td>
                    <td className="pr-3 font-mono text-xs">{i.host ?? "n/a"}</td>
                    <td className="pr-3 font-mono text-xs">{i.indicator_ip ?? "n/a"}</td>
                    <td className="pr-3 font-mono text-xs">{fmtTime(i.time, true)}</td>
                    <td className="pr-3 font-mono text-xs">{fmtDuration(i.tta_s)}</td>
                    <td className="font-mono text-xs">{fmtDuration(i.ttr_s)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <Empty>No incidents match.</Empty>}
        <p className="mt-3 text-[11px] text-muted">Times are measured from the triggering detection. <Tag>02</Tag> records them in its hash-chained audit log.</p>
      </Card>
    </>
  );
}
