import { useReducedMotion } from "motion/react";
import { useEffect, useRef, useState } from "react";
import { GLYPHS, rng, scrambleFrame } from "../lib/logic";

/** Cryptographic reveal: text resolves left to right out of random glyphs whenever `text` changes. */
export function TextScramble({ text, duration = 700, className, as: Tag = "span" }: {
  text: string; duration?: number; className?: string; as?: "span" | "p" | "div";
}) {
  const reduced = useReducedMotion();
  const [shown, setShown] = useState(reduced ? text : "");
  const frame = useRef(0);
  useEffect(() => {
    if (reduced || !text) {
      setShown(text);
      return;
    }
    const rand = rng(text.length * 7919);
    const start = performance.now();
    const tick = (now: number) => {
      const p = (now - start) / duration;
      setShown(scrambleFrame(text, p, rand, GLYPHS));
      if (p < 1) frame.current = requestAnimationFrame(tick);
    };
    frame.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame.current);
  }, [text, duration, reduced]);
  return <Tag className={className} aria-label={text}><span aria-hidden="true">{shown}</span></Tag>;
}
