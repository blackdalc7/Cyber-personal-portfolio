import { useEffect, useRef } from "react";
import { KONAMI, konamiStep } from "../lib/logic";

/** Calls `onTrigger` when ↑ ↑ ↓ ↓ ← → ← → B A is typed anywhere outside a text field. */
export function useKonami(onTrigger: () => void, sequence: string[] = KONAMI): void {
  const pos = useRef(0);
  const cb = useRef(onTrigger);
  cb.current = onTrigger;
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.target as HTMLElement | null)?.closest?.("input, textarea, select, [contenteditable]")) return;
      const r = konamiStep(pos.current, e.key, sequence);
      pos.current = r.position;
      if (r.done) cb.current();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [sequence]);
}
