import { animate, useReducedMotion } from "motion/react";
import { useEffect, useRef, useState } from "react";

/** Animated number that ticks from its previous value to the new one. `format` renders each frame. */
export function CountUp({ value, format = (n) => Math.round(n).toLocaleString("en"), duration = 0.9, className }: {
  value: number | null | undefined; format?: (n: number) => string; duration?: number; className?: string;
}) {
  const reduced = useReducedMotion();
  const prev = useRef(0);
  const [n, setN] = useState(reduced ? (value ?? 0) : 0);
  useEffect(() => {
    if (value === null || value === undefined || Number.isNaN(value)) return;
    if (reduced) {
      setN(value);
      prev.current = value;
      return;
    }
    const controls = animate(prev.current, value, { duration, ease: [0.16, 1, 0.3, 1], onUpdate: setN });
    prev.current = value;
    return () => controls.stop();
  }, [value, duration, reduced]);
  if (value === null || value === undefined || Number.isNaN(value)) return <span className={className}>n/a</span>;
  return <span className={className} aria-label={format(value)}><span aria-hidden="true">{format(n)}</span></span>;
}
