import { useReducedMotion } from "motion/react";
import { useCallback, useEffect, useRef, useState } from "react";
import { HEX, rng, scrambleFrame } from "../lib/logic";

/** Text that cycles through hex digits for a moment on hover or focus, then settles. Put it inside a button. */
export function GlitchText({ text, duration = 380 }: { text: string; duration?: number }) {
  const reduced = useReducedMotion();
  const [shown, setShown] = useState(text);
  const frame = useRef(0);
  const seed = useRef(1);
  useEffect(() => setShown(text), [text]);
  useEffect(() => () => cancelAnimationFrame(frame.current), []);

  const run = useCallback(() => {
    if (reduced) return;
    cancelAnimationFrame(frame.current);
    const rand = rng(seed.current++);
    const start = performance.now();
    const tick = (now: number) => {
      const p = (now - start) / duration;
      setShown(scrambleFrame(text, p, rand, HEX));
      if (p < 1) frame.current = requestAnimationFrame(tick);
    };
    frame.current = requestAnimationFrame(tick);
  }, [text, duration, reduced]);

  return (
    <span onMouseEnter={run} onFocus={run} aria-label={text} className="inline-block font-[inherit] tabular-nums">
      <span aria-hidden="true">{shown}</span>
    </span>
  );
}
