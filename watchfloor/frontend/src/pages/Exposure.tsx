import { useMemo, useState } from "react";
import { Topology } from "@portfolio/aegis-ui";
import { Card, Empty, ErrorBox, Kpi, Loading, PageHeader, Tag } from "../components/ui";
import { useLoad } from "../lib/data";
import { whatIf } from "../lib/logic";

export default function Exposure() {
  const expo = useLoad((s) => s.exposure());
  const [patched, setPatched] = useState<Set<string>>(new Set());

  const data = expo.data;
  const result = useMemo(() => (data ? whatIf(data.attack_paths, patched) : null), [data, patched]);
  const crown = useMemo(() => new Set(data?.attack_paths.map((p) => p.target) ?? []), [data]);
  const graph = useMemo(() => {
    if (!data || !result) return null;
    const aliveEdges = new Set(result.alive.flatMap((p) => p.steps.map((s) => `${s.from}>${s.to}`)));
    const aliveNodes = new Set(result.alive.flatMap((p) => p.path));
    return {
      nodes: data.graph.nodes.map((n) => ({
        id: n.id, label: n.label, kind: n.kind === "internet" ? "internet" : crown.has(n.id) ? "crown" : n.kind,
        flagged: !!n.cves?.some((c) => !patched.has(c.cve) && (c as { kev?: boolean }).kev),
        dim: n.id !== "internet" && !aliveNodes.has(n.id) && result.alive.length > 0,
      })),
      edges: data.graph.edges.map((e) => ({ id: e.id, source: e.source, target: e.target, label: `${e.port ?? ""} ${e.cve ?? ""}`.trim(),
        hot: aliveEdges.has(e.id), dim: !aliveEdges.has(e.id) })),
    };
  }, [data, result, crown, patched]);

  if (expo.error) return <ErrorBox error={expo.error} />;
  if (expo.loading) return <Loading />;
  if (!data || !result || !graph) return <Empty>No exposure data. Point WF_EXPOSURE_FILE at 04's findings.json.</Empty>;

  const cves = [...new Map(data.findings.map((f) => [f.cve, f])).values()].sort((a, b) => b.priority - a.priority);
  const toggle = (cve: string) => setPatched((p) => {
    const n = new Set(p);
    if (n.has(cve)) n.delete(cve); else n.add(cve);
    return n;
  });

  return (
    <>
      <PageHeader title="Exposure and attack paths">
        Project 04's scan of the lab, as a graph from the internet to the crown jewels. Tick a CVE to see which attack
        paths die if it is patched: this is how you pick the fix that removes the most risk.
      </PageHeader>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Kpi label="Attack paths" value={<span>{result.after}<span className="text-muted">/{result.before}</span></span>} tone={result.after ? "bad" : "good"} hint="still open" />
        <Kpi label="Crown jewels reachable" value={result.reachable.length} tone={result.reachable.length ? "bad" : "good"} hint={result.reachable.join(", ") || "none"} />
        <Kpi label="Patched (what-if)" value={patched.size} hint="CVEs ticked below" />
        <Kpi label="Entry points" value={data.entry_points.length} hint={data.entry_points.join(", ")} />
      </div>
      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2" scanlines title="Attack graph" subtitle="Red edges are open paths. Stars are crown jewels, the diamond is the internet.">
          <Topology nodes={graph.nodes} edges={graph.edges} direction="LR" roots={["internet"]} ariaLabel="Attack path graph" height={440}
            renderContext={(id) => {
              const node = data.graph.nodes.find((n) => n.id === id);
              if (!node) return null;
              const paths = result.alive.filter((p) => p.path.includes(id));
              return (
                <div className="space-y-2">
                  <div className="font-medium">{node.label} <span className="font-mono text-xs text-muted">{node.id}</span></div>
                  <div className="flex flex-wrap gap-1">{(node.cves ?? []).map((c) => (
                    <Tag key={c.cve} mono>{patched.has(c.cve) ? <s>{c.cve}</s> : c.cve}</Tag>))}{node.exposure && <Tag>{node.exposure}</Tag>}</div>
                  <p className="font-mono text-[11px] text-muted">{paths.length ? `on ${paths.length} open attack path(s)` : "not on any open path"}
                    {crown.has(id) && <span className="text-cyan"> · crown jewel</span>}</p>
                </div>
              );
            }} />
        </Card>
        <Card title="What if we patch…" subtitle="Ordered by 04's priority score (CVSS, EPSS, KEV, blast radius)">
          <ul className="max-h-[440px] space-y-1 overflow-y-auto">
            {cves.map((f) => (
              <li key={f.cve}>
                <label className="flex cursor-pointer items-center gap-2 px-2 py-1.5 text-sm hover:bg-panel-2">
                  <input type="checkbox" checked={patched.has(f.cve)} onChange={() => toggle(f.cve)} className="accent-[var(--ae-cyan)]" />
                  <span className="flex-1">
                    <span className="font-mono text-xs">{f.cve}</span>
                    <span className="block text-[11px] text-muted">{f.asset} · port {f.port} · CVSS {f.cvss} · EPSS {(f.epss * 100).toFixed(1)}%</span>
                  </span>
                  {f.kev && <span className="rounded bg-crit/15 px-1.5 text-[10px] font-semibold text-crit">KEV</span>}
                  {f.chokepoint > 0 && <Tag>chokepoint</Tag>}
                </label>
              </li>
            ))}
          </ul>
        </Card>
      </div>
    </>
  );
}
