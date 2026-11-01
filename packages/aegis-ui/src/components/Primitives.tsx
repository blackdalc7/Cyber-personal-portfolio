import { cva, type VariantProps } from "class-variance-authority";
import type { ButtonHTMLAttributes, ReactNode } from "react";
import { cn } from "../lib/cn";
import { ERROR_QUIPS, STATUS, quipFor, type StatusName } from "../lib/logic";
import { GlitchText } from "./GlitchText";

/** Glass panel with a 1px frame and bright corner ticks. `scanlines` adds the CRT overlay for charts. */
export function Panel({ title, subtitle, actions, children, className, scanlines, label }: {
  title?: ReactNode; subtitle?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string;
  scanlines?: boolean; label?: string;
}) {
  return (
    <section className={cn("ae-glass ae-ticks p-4", scanlines && "ae-scanlines", className)} aria-label={label}>
      {(title || actions) && (
        <header className="mb-3 flex items-start justify-between gap-3">
          <div className="min-w-0">
            {title && <h2 className="font-mono text-[11px] font-semibold uppercase tracking-[0.18em] text-muted">{title}</h2>}
            {subtitle && <p className="mt-1 text-xs text-muted/80">{subtitle}</p>}
          </div>
          {actions}
        </header>
      )}
      {children}
    </section>
  );
}

export const buttonVariants = cva(
  "inline-flex items-center gap-1.5 border px-3 py-1.5 font-mono text-xs uppercase tracking-wider transition disabled:opacity-40",
  {
    variants: {
      variant: {
        default: "border-line bg-panel-2 text-ink hover:border-cyan/60 hover:text-cyan",
        primary: "border-cyan bg-cyan/10 text-cyan hover:bg-cyan/20 hover:shadow-[var(--ae-glow)]",
        danger: "border-crimson/70 bg-crimson/10 text-crimson hover:bg-crimson/20",
        ghost: "border-transparent text-muted hover:text-ink",
      },
    },
    defaultVariants: { variant: "default" },
  },
);

/** shadcn-style button. `glitch` makes the label cycle through hex on hover. */
export function Button({ variant, className, children, glitch, ...rest }: ButtonHTMLAttributes<HTMLButtonElement> &
  VariantProps<typeof buttonVariants> & { glitch?: string }) {
  return (
    <button type="button" className={cn(buttonVariants({ variant }), className)} {...rest}>
      {glitch ? <GlitchText text={glitch} /> : children}
    </button>
  );
}

export function Kbd({ children }: { children: ReactNode }) {
  return <kbd className="border border-line bg-black/40 px-1.5 py-0.5 font-mono text-[10px] text-muted">{children}</kbd>;
}

/** Named result state, coloured from the shared status tokens. */
export function StatusBadge({ status, className }: { status: StatusName; className?: string }) {
  const s = STATUS[status];
  return (
    <span className={cn("inline-flex items-center gap-1 border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider", className)}
      style={{ color: `var(${s.varName})`, borderColor: `color-mix(in srgb, var(${s.varName}) 55%, transparent)`,
        background: `color-mix(in srgb, var(${s.varName}) 10%, transparent)` }}>
      <span aria-hidden="true">{s.glyph}</span>{s.label}
    </span>
  );
}

/** Empty state with a radial glow and a quip that stays the same for the same `quipKey`. */
export function SnarkyEmpty({ quipKey, children, quip }: { quipKey: string; children?: ReactNode; quip?: string }) {
  return (
    <div className="ae-empty-radial flex flex-col items-center justify-center gap-2 border border-dashed border-line px-6 py-10 text-center">
      <pre aria-hidden="true" className="font-mono text-[10px] leading-tight text-muted/70">{"  ( o_o)\n  /|  |\\\n   |  |"}</pre>
      <p className="font-mono text-sm text-ink">{quip ?? quipFor(quipKey)}</p>
      {children && <div className="max-w-md text-xs text-muted">{children}</div>}
    </div>
  );
}

/** Error box with a straight technical message and one line of personality. */
export function SnarkyError({ error, children }: { error: unknown; children?: ReactNode }) {
  const message = error instanceof Error ? error.message : String(error);
  return (
    <div role="alert" className="border border-crimson/50 bg-crimson/10 p-4 font-mono text-sm">
      <div className="text-crimson">✕ {message}</div>
      <div className="mt-1 text-xs text-muted">{quipFor(message, ERROR_QUIPS)}</div>
      {children}
    </div>
  );
}
