/** A quiet loading line. It announces itself to screen readers and shows a blinking underscore, nothing more. */
export function AsciiLoader({ label = "Loading" }: { label?: string }) {
  return (
    <div role="status" aria-live="polite" className="py-10 font-mono text-[13px] text-muted">
      {label}<span className="ae-caret" />
    </div>
  );
}

/** Progress text for longer waits (evidence collection, AI analysis). Kept as a named export for the consoles. */
export function HexCascade({ label = "Working" }: { rows?: number; label?: string }) {
  return (
    <div role="status" aria-label={label} className="py-2 font-mono text-[12px] text-muted">
      {label}<span className="ae-caret" />
    </div>
  );
}
