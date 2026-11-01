import cytoscape from "cytoscape";
import { AnimatePresence, motion } from "motion/react";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { cn } from "../lib/cn";

export interface TopoNode {
  id: string;
  label: string;
  kind?: string; // "internet" | "crown" | "host" | ... (becomes a class)
  flagged?: boolean;
  dim?: boolean;
}
export interface TopoEdge {
  id?: string;
  source: string;
  target: string;
  label?: string;
  hot?: boolean;
  dim?: boolean;
}

function tokens() {
  const css = getComputedStyle(document.documentElement);
  const v = (n: string) => css.getPropertyValue(n).trim();
  return { ink: v("--ae-ink"), muted: v("--ae-muted"), line: v("--ae-line-bright"), panel: v("--ae-panel-solid"),
    cyan: v("--ae-cyan"), amber: v("--ae-amber"), crimson: v("--ae-crimson"), green: v("--ae-green") };
}

/**
 * Interactive topology (Cytoscape): drag nodes to rearrange, scroll to zoom, click a node to open a glass context
 * card rendered by `renderContext`. Restyles itself when the theme or a hidden mode changes.
 */
export function Topology({ nodes, edges, height = 380, direction = "TB", roots, renderContext, onSelect, ariaLabel, className }: {
  nodes: TopoNode[]; edges: TopoEdge[]; height?: number; direction?: "TB" | "LR"; roots?: string[];
  renderContext?: (id: string) => ReactNode; onSelect?: (id: string | null) => void; ariaLabel: string; className?: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);
  const [sel, setSel] = useState<string | null>(null);
  const [themeTick, setThemeTick] = useState(0);
  const onSelectRef = useRef(onSelect);
  onSelectRef.current = onSelect;

  useEffect(() => {
    const on = () => setThemeTick((t) => t + 1);
    window.addEventListener("ae-theme", on);
    window.addEventListener("wf-theme", on);
    return () => { window.removeEventListener("ae-theme", on); window.removeEventListener("wf-theme", on); };
  }, []);

  useEffect(() => {
    if (!ref.current) return;
    const c = tokens();
    const ids = new Set(nodes.map((n) => n.id));
    const cy = cytoscape({
      container: ref.current,
      elements: [
        ...nodes.map((n) => ({ data: { ...n }, classes: [n.kind, n.flagged && "flagged", n.dim && "dim"].filter(Boolean).join(" ") })),
        ...edges.filter((e) => ids.has(e.source) && ids.has(e.target))
          .map((e, i) => ({ data: { ...e, id: e.id ?? `e${i}` }, classes: [e.hot && "hot", e.dim && "dim"].filter(Boolean).join(" ") })),
      ],
      style: [
        { selector: "node", style: { label: "data(label)", "font-size": 10, "font-family": "JetBrains Mono, monospace", color: c.ink,
          "text-valign": "bottom", "text-margin-y": 6, "background-color": c.panel, "border-width": 1.5, "border-color": c.muted,
          shape: "round-rectangle", width: 22, height: 22 } },
        { selector: "node.flagged", style: { "border-color": c.crimson, "background-color": c.crimson, "border-width": 2,
          "underlay-color": c.crimson, "underlay-opacity": 0.25, "underlay-padding": 6 } },
        { selector: "node.internet", style: { shape: "diamond", "border-color": c.amber, "background-color": c.amber } },
        { selector: "node.crown", style: { shape: "star", "border-color": c.cyan, width: 30, height: 30 } },
        { selector: "node.dim", style: { opacity: 0.3 } },
        { selector: "node:selected", style: { "border-color": c.cyan, "border-width": 3, "underlay-color": c.cyan, "underlay-opacity": 0.3, "underlay-padding": 8 } },
        { selector: "node:grabbed", style: { "underlay-color": c.cyan, "underlay-opacity": 0.4 } },
        { selector: "edge", style: { width: 1, "line-color": c.line, "target-arrow-color": c.line, "target-arrow-shape": "triangle",
          "curve-style": "bezier", label: "data(label)", "font-size": 8, "font-family": "JetBrains Mono, monospace", color: c.muted,
          "text-rotation": "autorotate", "text-background-color": c.panel, "text-background-opacity": 1, "text-background-padding": "2px" } },
        { selector: "edge.hot", style: { width: 2, "line-color": c.crimson, "target-arrow-color": c.crimson, "line-style": "solid" } },
        { selector: "edge.dim", style: { opacity: 0.25, "line-style": "dashed" } },
      ],
      layout: {
        name: "breadthfirst", directed: true, padding: 18, spacingFactor: direction === "LR" ? 1.15 : 1,
        roots: roots && roots.length ? roots : undefined,
        transform: direction === "LR" ? (_n: unknown, p: { x: number; y: number }) => ({ x: p.y, y: p.x }) : undefined,
      } as cytoscape.LayoutOptions,
      wheelSensitivity: 0.2, minZoom: 0.3, maxZoom: 2.5,
    });
    cy.on("tap", "node", (e) => { setSel(e.target.id()); onSelectRef.current?.(e.target.id()); });
    cy.on("tap", (e) => { if (e.target === cy) { setSel(null); onSelectRef.current?.(null); } });
    cyRef.current = cy;
    return () => { cy.destroy(); cyRef.current = null; };
  }, [nodes, edges, direction, roots, themeTick]);

  return (
    <div className={cn("relative", className)}>
      <div ref={ref} style={{ height }} className="w-full border border-line bg-black/20" role="img" aria-label={ariaLabel} />
      <div className="pointer-events-none absolute left-2 top-2 font-mono text-[10px] text-muted">drag nodes · scroll to zoom · click for context</div>
      <button type="button" onClick={() => cyRef.current?.fit(undefined, 18)}
        className="absolute right-2 top-2 border border-line bg-panel-solid/80 px-2 py-0.5 font-mono text-[10px] text-muted hover:text-cyan">fit</button>
      <AnimatePresence>
        {sel && renderContext && (
          <motion.div key={sel} initial={{ opacity: 0, x: 12 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: 12 }}
            className="ae-glass absolute bottom-2 right-2 w-[min(320px,80%)] p-3 text-sm">
            <button type="button" aria-label="Close context" onClick={() => { setSel(null); cyRef.current?.$(":selected").unselect(); }}
              className="absolute right-2 top-1 font-mono text-xs text-muted hover:text-ink">×</button>
            {renderContext(sel)}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
