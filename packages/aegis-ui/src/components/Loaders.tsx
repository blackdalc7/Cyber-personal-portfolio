import { useEffect, useMemo, useState } from "react";
import { hexdumpLine, rng } from "../lib/logic";

const SPIN = ["[    ]", "[=   ]", "[==  ]", "[=== ]", "[ ===]", "[  ==]", "[   =]", "[    ]", "[   =]", "[  ==]", "[ ===]", "[====]"];
const LINES = [
  "querying the lake",
  "decompressing parquet",
  "asking DuckDB nicely",
  "reticulating kill chains",
  "bribing the API with coffee",
  "grepping the void",
];

/** ASCII loader with rotating, slightly sarcastic status lines. Replaces spinners everywhere. */
export function AsciiLoader({ label }: { label?: string }) {
  const [i, setI] = useState(0);
  useEffect(() => {
    const id = window.setInterval(() => setI((x) => x + 1), 110);
    return () => window.clearInterval(id);
  }, []);
  return (
    <div role="status" aria-live="polite" className="p-6 font-mono text-sm text-cyan">
      <span>{SPIN[i % SPIN.length]}</span>{" "}
      <span className="text-muted">{label ?? LINES[Math.floor(i / 18) % LINES.length]}</span>
      <span className="ae-caret" />
    </div>
  );
}

/** A falling hexdump: for longer waits (evidence collection, AI analysis). */
export function HexCascade({ rows = 8, label }: { rows?: number; label?: string }) {
  const [tick, setTick] = useState(0);
  const rand = useMemo(() => rng(42), []);
  const [lines, setLines] = useState<string[]>([]);
  useEffect(() => {
    const id = window.setInterval(() => setTick((t) => t + 1), 90);
    return () => window.clearInterval(id);
  }, []);
  useEffect(() => {
    const bytes = Array.from({ length: 16 }, () => Math.floor(rand() * 256));
    setLines((l) => [...l.slice(-(rows - 1)), hexdumpLine(tick * 16, bytes)]);
  }, [tick, rows, rand]);
  return (
    <div role="status" aria-label={label ?? "Working"} className="overflow-hidden p-4 font-mono text-[11px] leading-5">
      {lines.map((l, i) => (
        <div key={`${tick}-${i}`} className="whitespace-pre text-green" style={{ opacity: 0.25 + (0.75 * (i + 1)) / lines.length }}>{l}</div>
      ))}
      {label && <div className="mt-2 text-muted">{label}<span className="ae-caret" /></div>}
    </div>
  );
}
