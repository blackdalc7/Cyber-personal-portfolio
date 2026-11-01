// Watchfloor's page vocabulary, built on the shared Aegis Editorial design system (packages/aegis-ui/DESIGN.md).
import {
  AsciiLoader, EmptyState, ErrorNotice, Panel, StatusBadge, Button as AeButton, cn, quipFor,
} from "@portfolio/aegis-ui";
import type { ReactNode } from "react";
import type { CoverageOutcome } from "../api/types";
import { severityName } from "../lib/logic";

/** A page section (strong top rule, serif heading). Named Card for continuity with earlier pages. */
export function Card({ title, actions, children, className, subtitle }: {
  title?: ReactNode; subtitle?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string;
}) {
  return <Panel title={title} subtitle={subtitle} actions={actions} className={className}>{children}</Panel>;
}

const TONE = { default: "text-ink", good: "text-good", warn: "text-warn", bad: "text-bad" } as const;

/** A key figure: short rule above, mono label, serif value, optional one-line note. Numbers render as-is. */
export function Kpi({ label, value, hint, tone = "default", format }: {
  label: string; value: ReactNode | number | null; hint?: ReactNode; tone?: keyof typeof TONE; format?: (n: number) => string;
}) {
  const shown = value === null ? "n/a" : typeof value === "number" ? (format ? format(value) : value.toLocaleString("en-GB")) : value;
  return (
    <div className="min-w-0 border-t border-line pt-2">
      <div className="ae-label">{label}</div>
      <div className={cn("mt-1 font-serif text-[1.75rem] font-medium leading-none tabular-nums", TONE[tone])}>{shown}</div>
      {hint && <div className="mt-1.5 truncate text-[12px] text-muted">{hint}</div>}
    </div>
  );
}

const SEV_CLASS: Record<string, string> = {
  critical: "bg-crit text-bg",
  high: "text-bad border-bad",
  medium: "text-warn border-warn",
  low: "text-accent border-accent",
  info: "text-muted border-line",
  unknown: "text-muted border-line",
};

/** Severity as a small ruled label. Critical is the only filled one, so it stands out without colour alone. */
export function Severity({ id }: { id: number | null | undefined }) {
  const name = severityName(id);
  return (
    <span className={cn("inline-flex shrink-0 items-center border px-1.5 font-mono text-[11px] leading-5",
      SEV_CLASS[name] ?? SEV_CLASS.unknown, name === "critical" && "border-crit")}>
      {name}
    </span>
  );
}

export function OutcomeChip({ outcome }: { outcome: CoverageOutcome }) {
  return <StatusBadge status={outcome} />;
}

/** Plain metadata tag: hairline frame, no fill. */
export function Tag({ children, mono }: { children: ReactNode; mono?: boolean }) {
  return (
    <span className={cn("inline-flex items-center border border-line px-1.5 text-[11px] leading-5 text-muted", mono && "font-mono")}>
      {children}
    </span>
  );
}

export function Button({ children, onClick, variant = "default", disabled, title, ariaLabel }: {
  children?: ReactNode; onClick?: () => void; variant?: "default" | "primary" | "ghost" | "danger"; disabled?: boolean;
  title?: string; ariaLabel?: string;
}) {
  return (
    <AeButton variant={variant} onClick={onClick} disabled={disabled} title={title} aria-label={ariaLabel}>
      {children}
    </AeButton>
  );
}

/** Link styled as a primary action (used for "Play" style calls to action). */
export const actionLinkClass = "inline-flex items-center gap-1.5 border border-accent bg-accent px-3 py-1.5 text-[13px] font-medium text-bg hover:border-ink hover:bg-ink";

export function Loading({ label }: { label?: string }) {
  return <AsciiLoader label={label} />;
}

export function ErrorBox({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : String(error);
  return <ErrorNotice error={error}>{message.startsWith("401") ? <TokenForm /> : <p className="mt-1 text-[13px] text-muted">{quipFor(message)}</p>}</ErrorNotice>;
}

/** The hub asks for WF_HUB_TOKEN; keep it in this browser only and reload. */
function TokenForm() {
  const save = (form: HTMLFormElement) => {
    const value = new FormData(form).get("token");
    try {
      localStorage.setItem("wf.token", String(value ?? "").trim());
    } catch {
      /* storage blocked: nothing to persist */
    }
    window.location.reload();
  };
  return (
    <form className="mt-3 flex gap-2" onSubmit={(e) => { e.preventDefault(); save(e.currentTarget); }}>
      <input name="token" type="password" autoComplete="off" placeholder="Hub token (WF_HUB_TOKEN)" aria-label="Hub token"
        className="flex-1 border border-rule bg-panel-solid px-3 py-1.5 font-mono text-sm text-ink outline-none focus:border-accent" />
      <button type="submit" className="border border-rule px-3 py-1.5 text-[13px] hover:bg-ink hover:text-bg">Save token</button>
    </form>
  );
}

/**
 * Empty state. A plain-string child becomes the message itself; richer children are shown as guidance under a
 * stable default sentence (chosen by `quipKey`).
 */
export function Empty({ children, quipKey = "empty" }: { children?: ReactNode; quipKey?: string }) {
  if (typeof children === "string") return <EmptyState message={children} />;
  return <EmptyState message={quipFor(quipKey)}>{children}</EmptyState>;
}

/**
 * Asymmetric page header: serif title on the left seven columns, the standfirst (what the page shows and where the
 * data came from) on the right five, closed by a strong rule. `kicker` is a small section label above the title.
 */
export function PageHeader({ title, children, actions, kicker }: { title: string; children?: ReactNode; actions?: ReactNode; kicker?: string }) {
  return (
    <header className="mb-8 border-b border-rule pb-5">
      <div className="grid gap-x-10 gap-y-3 lg:grid-cols-12">
        <div className="lg:col-span-7">
          {kicker && <div className="ae-label mb-2">{kicker}</div>}
          <h1 className="text-[2.25rem] font-semibold text-ink">{title}</h1>
        </div>
        {children && <p className="max-w-prose text-[14px] leading-relaxed text-muted lg:col-span-5 lg:pt-3">{children}</p>}
      </div>
      {actions && <div className="mt-4 flex flex-wrap items-center gap-2">{actions}</div>}
    </header>
  );
}
