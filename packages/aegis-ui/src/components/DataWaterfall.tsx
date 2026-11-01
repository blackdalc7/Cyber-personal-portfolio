import { useReducedMotion } from "motion/react";
import { useEffect, useRef } from "react";

/**
 * A muted, blurred waterfall of live telemetry behind the page: each new line drops down one of several columns
 * and fades out. Purely decorative (aria-hidden, pointer-events none). Feed it short strings, newest last.
 * With reduced motion it renders nothing.
 */
export function DataWaterfall({ lines, columns = 7, opacity = 0.11, speed = 38 }: {
  lines: string[]; columns?: number; opacity?: number; speed?: number;
}) {
  const reduced = useReducedMotion();
  const canvas = useRef<HTMLCanvasElement>(null);
  const queue = useRef<string[]>([]);
  const seen = useRef(0);

  useEffect(() => {
    // Only enqueue lines we have not shown yet; loop the feed when it runs dry so the background never stalls.
    const fresh = lines.slice(Math.max(0, Math.min(seen.current, lines.length)));
    queue.current.push(...fresh);
    seen.current = lines.length;
  }, [lines]);

  useEffect(() => {
    if (reduced) return;
    const el = canvas.current;
    const ctx = el?.getContext("2d");
    if (!el || !ctx) return;
    let raf = 0;
    let last = performance.now();
    let spawn = 0;
    let cursor = 0;
    const drops: { x: number; y: number; text: string; hot: boolean }[] = [];
    const resize = () => {
      el.width = el.clientWidth * devicePixelRatio;
      el.height = el.clientHeight * devicePixelRatio;
      ctx.setTransform(devicePixelRatio, 0, 0, devicePixelRatio, 0, 0);
    };
    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(el);
    const css = getComputedStyle(document.documentElement);
    const tick = (now: number) => {
      const dt = Math.min(0.1, (now - last) / 1000);
      last = now;
      spawn -= dt;
      if (spawn <= 0) {
        const text = queue.current.shift() ?? (lines.length ? lines[cursor++ % lines.length] : "");
        if (text) {
          const col = Math.floor(Math.random() * columns);
          drops.push({ x: (col + 0.08) * (el.clientWidth / columns), y: -14, text: text.slice(0, 64), hot: /finding|critical|high|alert/i.test(text) });
        }
        spawn = queue.current.length ? 0.12 : 0.5;
      }
      ctx.clearRect(0, 0, el.clientWidth, el.clientHeight);
      ctx.font = "11px 'JetBrains Mono', monospace";
      const green = css.getPropertyValue("--ae-green").trim() || "#39ff88";
      const cyan = css.getPropertyValue("--ae-cyan").trim() || "#22e4ff";
      const red = css.getPropertyValue("--ae-crimson").trim() || "#ff3b5c";
      for (let i = drops.length - 1; i >= 0; i--) {
        const d = drops[i];
        d.y += speed * dt;
        const fade = Math.max(0, 1 - d.y / el.clientHeight);
        ctx.globalAlpha = fade;
        ctx.fillStyle = d.hot ? red : i % 3 ? green : cyan;
        ctx.fillText(d.text, d.x, d.y);
        if (d.y > el.clientHeight + 20) drops.splice(i, 1);
      }
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reduced, columns, speed]);

  if (reduced) return null;
  return (
    <canvas ref={canvas} aria-hidden="true" className="pointer-events-none fixed inset-0 -z-10 h-full w-full"
      style={{ opacity, filter: "blur(1.2px)", maskImage: "linear-gradient(to bottom, black 30%, transparent 95%)" }} />
  );
}
