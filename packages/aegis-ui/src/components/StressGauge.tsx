import { motion, useReducedMotion } from "motion/react";
import { analystStress, type StressInput } from "../lib/logic";
import { CountUp } from "./CountUp";

/** The Analyst Stress Index: a half-moon gauge plus the coffee it will take to get through the shift. */
export function StressGauge(props: StressInput & { className?: string }) {
  const reduced = useReducedMotion();
  const r = analystStress(props);
  const angle = -90 + (r.score / 100) * 180;
  const color = r.score < 40 ? "var(--ae-green)" : r.score < 65 ? "var(--ae-amber)" : "var(--ae-crimson)";
  const arc = (from: number, to: number) => {
    const p = (a: number) => [60 + 48 * Math.cos(((a - 180) * Math.PI) / 180), 60 + 48 * Math.sin(((a - 180) * Math.PI) / 180)];
    const [x1, y1] = p(from);
    const [x2, y2] = p(to);
    return `M ${x1} ${y1} A 48 48 0 0 1 ${x2} ${y2}`;
  };
  return (
    <div className={props.className}>
      <svg viewBox="0 0 120 70" className="mx-auto w-full max-w-[220px]" role="img"
        aria-label={`Analyst stress ${r.score} of 100: ${r.label}`}>
        <path d={arc(0, 72)} stroke="var(--ae-green)" strokeWidth="6" fill="none" opacity="0.35" />
        <path d={arc(72, 117)} stroke="var(--ae-amber)" strokeWidth="6" fill="none" opacity="0.35" />
        <path d={arc(117, 180)} stroke="var(--ae-crimson)" strokeWidth="6" fill="none" opacity="0.35" />
        {Array.from({ length: 11 }, (_, i) => {
          const a = ((i * 18 - 180) * Math.PI) / 180;
          return <line key={i} x1={60 + 40 * Math.cos(a)} y1={60 + 40 * Math.sin(a)} x2={60 + 44 * Math.cos(a)} y2={60 + 44 * Math.sin(a)} stroke="var(--ae-muted)" strokeWidth="0.6" />;
        })}
        <motion.g initial={{ rotate: -90 }} animate={{ rotate: angle }} style={{ originX: "60px", originY: "60px" }}
          transition={reduced ? { duration: 0 } : { type: "spring", stiffness: 60, damping: 9 }}>
          <line x1="60" y1="60" x2="60" y2="18" stroke={color} strokeWidth="2" strokeLinecap="round" />
        </motion.g>
        <circle cx="60" cy="60" r="3.5" fill={color} />
      </svg>
      <div className="mt-1 text-center">
        <div className="font-mono text-2xl font-semibold" style={{ color }}><CountUp value={r.score} />/100</div>
        <div className="text-xs uppercase tracking-widest text-muted">{r.label}</div>
        <div className="mt-2 font-mono text-lg" aria-label={`${r.cups} coffees required`} title="Caffeine requirement">
          {"☕".repeat(r.cups) || "🫖"}
        </div>
        <p className="mt-1 text-[11px] italic text-muted">{r.quip}</p>
      </div>
    </div>
  );
}
