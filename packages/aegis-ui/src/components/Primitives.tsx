import { cva, type VariantProps } from "class-variance-authority";
import type { ButtonHTMLAttributes, ReactNode } from "react";
import { cn } from "../lib/cn";
import { STATUS, type StatusName } from "../lib/logic";

/**
 * A section of a page: a strong rule on top, a serif heading, then content on the page background.
 * Deliberately not a boxed card (see DESIGN.md, "Sections, not cards").
 */
export function Panel({ title, subtitle, actions, children, className, label }: {
  title?: ReactNode; subtitle?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; label?: string;
}) {
  return (
    <section className={cn("ae-section min-w-0", className)} aria-label={label}>
      {(title || actions) && (
        <header className="mb-3 flex items-start justify-between gap-4">
          <div className="min-w-0">
            {title && <h2 className="text-[1.0625rem] font-semibold text-ink">{title}</h2>}
            {subtitle && <p className="mt-0.5 text-[13px] text-muted">{subtitle}</p>}
          </div>
          {actions}
        </header>
      )}
      {children}
    </section>
  );
}

/** Button styles. Hover is an instant colour swap; there is no transition, scale or glow. */
export const buttonVariants = cva(
  "inline-flex items-center gap-1.5 border px-3 py-1.5 text-[13px] font-medium disabled:cursor-not-allowed disabled:opacity-40",
  {
    variants: {
      variant: {
        default: "border-rule text-ink hover:bg-ink hover:text-bg",
        primary: "border-accent bg-accent text-bg hover:bg-ink hover:border-ink",
        danger: "border-bad text-bad hover:bg-bad hover:text-bg",
        ghost: "border-transparent text-muted hover:text-ink",
      },
    },
    defaultVariants: { variant: "default" },
  },
);

/** A plain button using `buttonVariants`. */
export function Button({ variant, className, children, ...rest }: ButtonHTMLAttributes<HTMLButtonElement> &
  VariantProps<typeof buttonVariants>) {
  return (
    <button type="button" className={cn(buttonVariants({ variant }), className)} {...rest}>
      {children}
    </button>
  );
}

/** A keyboard key, set in mono with a hairline frame. */
export function Kbd({ children }: { children: ReactNode }) {
  return <kbd className="border border-line px-1.5 py-px font-mono text-[10px] text-muted">{children}</kbd>;
}

/** Named result state: a glyph plus a label in the status colour. Colour is never the only signal. */
export function StatusBadge({ status, className }: { status: StatusName; className?: string }) {
  const s = STATUS[status];
  return (
    <span className={cn("inline-flex items-center gap-1 font-mono text-[11px] font-medium", className)}
      style={{ color: `var(${s.varName})` }}>
      <span aria-hidden="true">{s.glyph}</span>{s.label}
    </span>
  );
}

/** Empty state: one factual sentence, plus optional guidance on how to fill it. */
export function EmptyState({ message = "Nothing to show yet.", children }: { message?: string; children?: ReactNode }) {
  return (
    <div className="border-t border-dashed border-line py-8">
      <p className="text-sm text-ink">{message}</p>
      {children && <div className="mt-1 max-w-xl text-[13px] text-muted">{children}</div>}
    </div>
  );
}

/** Error notice: what failed, then optional guidance or a recovery form. */
export function ErrorNotice({ error, children }: { error: unknown; children?: ReactNode }) {
  const message = error instanceof Error ? error.message : String(error);
  return (
    <div role="alert" className="border-l-2 border-bad py-2 pl-4">
      <p className="text-sm font-medium text-bad">Could not load this view</p>
      <p className="mt-0.5 font-mono text-xs text-ink">{message}</p>
      {children}
    </div>
  );
}
