import * as echarts from "echarts";
import { useEffect, useRef, useState } from "react";

/** Read the current theme tokens so charts follow the light/dark switch. */
export function chartColors() {
  const css = getComputedStyle(document.documentElement);
  const v = (name: string) => css.getPropertyValue(name).trim();
  return {
    ink: v("--ae-ink"), muted: v("--ae-muted"), line: v("--ae-line"), panel: v("--ae-paper"),
    accent: v("--ae-accent"), good: v("--ae-good"), warn: v("--ae-warn"), bad: v("--ae-bad"), crit: v("--ae-crit"),
  };
}

export function EChart({ option, height = 240, ariaLabel, onClick }: {
  option: echarts.EChartsCoreOption; height?: number; ariaLabel: string;
  onClick?: (params: { name: string; dataIndex: number; seriesName?: string }) => void;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const chart = useRef<echarts.ECharts | null>(null);

  useEffect(() => {
    if (!ref.current) return;
    chart.current = echarts.init(ref.current, undefined, { renderer: "svg" });
    const ro = new ResizeObserver(() => chart.current?.resize());
    ro.observe(ref.current);
    return () => {
      ro.disconnect();
      chart.current?.dispose();
      chart.current = null;
    };
  }, []);

  useEffect(() => {
    chart.current?.setOption({ backgroundColor: "transparent", animationDuration: 200, animationEasing: "linear",
      textStyle: { fontFamily: "IBM Plex Mono, ui-monospace, monospace" }, ...option }, true);
  }, [option]);

  useEffect(() => {
    const c = chart.current;
    if (!c || !onClick) return;
    const handler = (p: unknown) => onClick(p as { name: string; dataIndex: number; seriesName?: string });
    c.on("click", handler);
    return () => {
      c.off("click", handler);
    };
  }, [onClick]);

  return <div ref={ref} style={{ height }} role="img" aria-label={ariaLabel} className="w-full" />;
}

/** Re-render charts when the theme or a hidden display mode changes (colours come from CSS variables). */
export function useThemeVersion(): number {
  const [v, setV] = useState(0);
  useEffect(() => {
    const on = () => setV((x) => x + 1);
    window.addEventListener("wf-theme", on);
    window.addEventListener("ae-theme", on);
    return () => {
      window.removeEventListener("wf-theme", on);
      window.removeEventListener("ae-theme", on);
    };
  }, []);
  return v;
}
