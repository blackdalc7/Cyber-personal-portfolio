import { AnimatePresence, motion } from "motion/react";
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useKonami } from "../hooks/useKonami";

type Mode = "normal" | "phosphor" | "deface";

interface ModeApi {
  mode: Mode;
  /** Green-phosphor terminal for `ms` (the Konami reward). */
  phosphor: (ms?: number) => void;
  deface: boolean;
  setDeface: (on: boolean) => void;
}

const Ctx = createContext<ModeApi | null>(null);

export function useModes(): ModeApi {
  const c = useContext(Ctx);
  if (!c) throw new Error("ModeProvider missing");
  return c;
}

const SKULL = String.raw`
            ______
         .-"      "-.
        /            \
       |              |
       |,  .-.  .-.  ,|
       | )(__/  \__)( |
       |/     /\     \|
       (_     ^^     _)
        \__|IIIIII|__/
         | \IIIIII/ |
         \          /
          '--------'`;

/**
 * Hidden display modes. Konami turns the UI into a 1990s green-phosphor terminal for 10 seconds;
 * "deface" (a toggle in settings) shows what the console would look like if the SOC itself were owned.
 * Both are cosmetic: they set `data-mode` on <html> and never touch data or actions.
 */
export function ModeProvider({ children, product = "the SOC" }: { children: ReactNode; product?: string }) {
  const [mode, setMode] = useState<Mode>("normal");
  const [deface, setDefaceState] = useState(false);
  const timer = useRef<number | undefined>(undefined);

  const phosphor = useCallback((ms = 10_000) => {
    window.clearTimeout(timer.current);
    setMode("phosphor");
    timer.current = window.setTimeout(() => setMode((m) => (m === "phosphor" ? "normal" : m)), ms);
  }, []);

  const setDeface = useCallback((on: boolean) => {
    setDefaceState(on);
    setMode(on ? "deface" : "normal");
  }, []);

  useKonami(() => phosphor());

  useEffect(() => {
    const root = document.documentElement;
    if (mode === "normal") delete root.dataset.mode;
    else root.dataset.mode = mode;
    window.dispatchEvent(new Event("ae-theme"));
  }, [mode]);

  useEffect(() => {
    if (!deface) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setDeface(false);
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [deface, setDeface]);

  useEffect(() => () => window.clearTimeout(timer.current), []);

  const api = useMemo(() => ({ mode, phosphor, deface, setDeface }), [mode, phosphor, deface, setDeface]);
  return (
    <Ctx.Provider value={api}>
      {children}
      <AnimatePresence>
        {mode === "phosphor" && (
          <motion.div key="phosphor" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="ae-surface pointer-events-none fixed bottom-4 left-1/2 z-[9999] -translate-x-1/2 px-4 py-2 font-mono text-xs text-ink"
            role="status">
            Phosphor preview. Reverting in 10 seconds.<span className="ae-caret" />
          </motion.div>
        )}
        {deface && (
          <motion.div key="deface" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="fixed inset-0 z-[9999] flex items-center justify-center bg-[#140504]/95 p-6" role="dialog" aria-modal="true"
            aria-label="Deface mode simulation" onClick={() => setDeface(false)}>
            <div className="max-w-xl text-center font-mono text-[#ff6b5e]">
              <pre className="mx-auto inline-block text-left text-[10px] leading-tight sm:text-xs">{SKULL}</pre>
              <p className="mt-4 text-2xl font-bold tracking-widest">
                H4CK3D BY TH3 1NT3RN</p>
              <p className="mt-2 text-sm">all your logs are belong to us. {product} has been 0wn3d.</p>
              <p className="mt-6 font-sans text-sm text-[#f3d9d5]">
                Simulation only. This is what a compromised console looks like, so you know to trust nothing on it.
                Nothing was changed. Click anywhere or press Esc to restore.</p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </Ctx.Provider>
  );
}
