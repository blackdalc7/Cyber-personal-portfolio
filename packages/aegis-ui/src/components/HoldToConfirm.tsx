import { animate, motion, useMotionValue, useReducedMotion, useTransform } from "motion/react";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { cn } from "../lib/cn";
import { GlitchText } from "./GlitchText";

type Tone = "crimson" | "cyan" | "amber";
const TONE: Record<Tone, { ring: string; fill: string; text: string }> = {
  crimson: { ring: "border-crimson/70", fill: "bg-crimson/30", text: "text-crimson" },
  cyan: { ring: "border-cyan/70", fill: "bg-cyan/25", text: "text-cyan" },
  amber: { ring: "border-amber/70", fill: "bg-amber/25", text: "text-amber" },
};

/**
 * High-friction confirmation: the action fires only after the button is held for `duration` ms
 * (mouse, touch, or Space/Enter held down). Releasing early drains the bar. Use for anything destructive.
 */
export function HoldToConfirm({ label, onConfirm, duration = 1500, tone = "crimson", disabled, disabledReason, holdingLabel = "Keep holding…", icon, className }: {
  label: string; onConfirm: () => void | Promise<void>; duration?: number; tone?: Tone; disabled?: boolean;
  disabledReason?: string; holdingLabel?: string; icon?: ReactNode; className?: string;
}) {
  const reduced = useReducedMotion();
  const progress = useMotionValue(0);
  const width = useTransform(progress, (p) => `${p * 100}%`);
  const ctrl = useRef<ReturnType<typeof animate> | null>(null);
  const [holding, setHolding] = useState(false);
  const [busy, setBusy] = useState(false);
  const t = TONE[tone];

  useEffect(() => () => ctrl.current?.stop(), []);

  const start = () => {
    if (disabled || busy) return;
    setHolding(true);
    ctrl.current?.stop();
    ctrl.current = animate(progress, 1, {
      duration: (duration / 1000) * (1 - progress.get()),
      ease: "linear",
      onComplete: async () => {
        setHolding(false);
        setBusy(true);
        try {
          await onConfirm();
        } finally {
          setBusy(false);
          progress.set(0);
        }
      },
    });
  };
  const cancel = () => {
    if (!holding) return;
    setHolding(false);
    ctrl.current?.stop();
    ctrl.current = animate(progress, 0, { duration: reduced ? 0 : 0.25 });
  };

  return (
    <motion.button type="button" disabled={disabled || busy} title={disabled ? disabledReason : `Hold for ${(duration / 1000).toFixed(1)}s`}
      aria-label={`${label} (press and hold to confirm)`} aria-disabled={disabled}
      onPointerDown={start} onPointerUp={cancel} onPointerLeave={cancel} onPointerCancel={cancel}
      onKeyDown={(e) => { if ((e.key === " " || e.key === "Enter") && !e.repeat) { e.preventDefault(); start(); } }}
      onKeyUp={(e) => { if (e.key === " " || e.key === "Enter") cancel(); }}
      whileTap={disabled ? undefined : { scale: 0.98 }}
      className={cn("relative inline-flex select-none items-center gap-2 overflow-hidden border px-4 py-2 font-mono text-sm uppercase tracking-wider",
        t.ring, t.text, "bg-black/30 disabled:cursor-not-allowed disabled:opacity-40", className)}>
      <motion.span aria-hidden="true" className={cn("absolute inset-y-0 left-0", t.fill)} style={{ width }} />
      <span className="relative flex items-center gap-2">
        {icon}
        {busy ? "Executing…" : holding ? holdingLabel : <GlitchText text={label} />}
      </span>
    </motion.button>
  );
}

/**
 * "Slide to isolate": drag the knob all the way right to execute. A red gradient blooms out of the knob as it
 * travels, so the gesture feels heavier the closer it gets. Keyboard: focus the knob and press → four times.
 */
export function SlideToExecute({ label, onExecute, tone = "crimson", disabled, disabledReason, className, doneLabel = "Sent" }: {
  label: string; onExecute: () => void | Promise<void>; tone?: Tone; disabled?: boolean; disabledReason?: string;
  className?: string; doneLabel?: string;
}) {
  const track = useRef<HTMLDivElement>(null);
  const x = useMotionValue(0);
  const [max, setMax] = useState(200);
  const [state, setState] = useState<"idle" | "busy" | "done">("idle");
  const t = TONE[tone];
  const rgb = tone === "crimson" ? "255 59 92" : tone === "amber" ? "255 178 36" : "34 228 255";
  const bloom = useTransform(x, (v) => {
    const p = max > 0 ? Math.min(1, v / max) : 0;
    return `radial-gradient(circle at ${v + 22}px 50%, rgb(${rgb} / ${0.15 + 0.5 * p}) 0px, rgb(${rgb} / ${0.08 + 0.25 * p}) ${30 + p * max}px, transparent ${60 + p * max * 1.4}px)`;
  });
  const labelOpacity = useTransform(x, (v) => 1 - Math.min(0.8, v / Math.max(max, 1)));
  useEffect(() => {
    const el = track.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setMax(Math.max(40, el.clientWidth - 44)));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  const settle = async () => {
    if (x.get() >= max * 0.92 && state === "idle") {
      animate(x, max, { duration: 0.1 });
      setState("busy");
      try {
        await onExecute();
        setState("done");
        window.setTimeout(() => { setState("idle"); animate(x, 0, { type: "spring", stiffness: 300, damping: 30 }); }, 2200);
      } catch {
        setState("idle");
        animate(x, 0, { type: "spring", stiffness: 400, damping: 30 });
      }
      return;
    }
    animate(x, 0, { type: "spring", stiffness: 400, damping: 30 });
  };
  const off = disabled || state !== "idle";
  return (
    <div ref={track} title={disabled ? disabledReason : undefined}
      className={cn("relative h-11 min-w-[240px] select-none overflow-hidden border bg-black/40", t.ring, disabled && "opacity-40", className)}>
      <motion.div aria-hidden="true" className="absolute inset-0" style={{ background: bloom }} />
      <motion.span style={{ opacity: labelOpacity }}
        className={cn("pointer-events-none absolute inset-0 flex items-center justify-center pl-8 font-mono text-[11px] uppercase tracking-[0.25em]", t.text)}>
        {state === "busy" ? "executing…" : state === "done" ? doneLabel : <>{label} »»</>}
      </motion.span>
      <motion.button type="button" aria-label={`${label}: slide to execute`} disabled={off}
        drag={off ? false : "x"} dragConstraints={{ left: 0, right: max }} dragElastic={0} dragMomentum={false}
        style={{ x }} onDragEnd={settle}
        onKeyDown={(e) => {
          if (e.key === "ArrowRight" && !off) {
            e.preventDefault();
            const next = Math.min(max, x.get() + max / 4);
            x.set(next);
            if (next >= max) void settle();
          } else if (e.key === "Escape" || e.key === "ArrowLeft") {
            animate(x, 0, { duration: 0.15 });
          }
        }}
        className={cn("absolute left-0.5 top-0.5 z-10 flex h-10 w-10 cursor-grab items-center justify-center border bg-panel-solid font-mono text-lg active:cursor-grabbing", t.ring, t.text)}>
        {state === "done" ? "✓" : "›"}
      </motion.button>
    </div>
  );
}
