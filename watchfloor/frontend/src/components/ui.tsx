// Watchfloor's page vocabulary, built on the shared Aegis design system (packages/aegis-ui).
import {
  AsciiLoader, CountUp, Panel, SnarkyEmpty, SnarkyError, StatusBadge, Button as AeButton, cn,
} from "@portfolio/aegis-ui";
import type { ReactNode } from "react";
import type { CoverageOutcome } from "../api/types";
import { severityName } from "../lib/logic";

export function Card({ title, actions, children, className, subtitle, scanlines }: {
  title?: ReactNode; subtitle?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; scanlines?: boolean;
}) {
  return <Panel title={title} subtitle={subtitle} actions={actions} className={className} scanlines={scanlines}>{children}</Panel>;
}

const TONE = { default: "text-ink", good: "text-green", warn: "text-amber", bad: "text-crimson" } as const;

/** KPI tile. Pass a number (plus optional `format`) to get an animated counter; any other node renders as-is. */
export function Kpi({ label, value, hint, tone = "default", format }: {
  label: string; value: ReactNode | number | null; hint?: ReactNode; tone?: keyof typeof TONE; format?: (n: number) => string;
}) {
  return (
    <div className="ae-glass ae-ticks px-4 py-3">
      <div className="font-mono text-[10px] uppercase tracking-[0.2em] text-muted">{label}</div>
      <div className={cn("mt-1 font-mono text-2xl font-semibold tabular-nums", TONE[tone], tone !== "default" && "ae-neon-text")}>
        {typeof value === "number" || value === null ? <CountUp value={value} format={format} /> : value}
      </div>
      {hint && <div className="mt-0.5 truncate text-xs text-muted">{hint}</div>}
    </div>
  );
}

const SEV_CLASS: Record<string, string> = {
  critical: "border-crit/60 bg-crit/15 text-crit",
  high: "border-crimson/50 bg-crimson/10 text-crimson",
  medium: "border-amber/50 bg-amber/10 text-amber",
  low: "border-cyan/40 bg-cyan/5 text-cyan",
  info: "border-line text-muted",
  unknown: "border-line text-muted",
};

export function Severity({ id }: { id: number | null | undefined }) {
  const name = severityName(id);
  return (
    <span className={cn("inline-flex items-center border px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider",
      SEV_CLASS[name] ?? SEV_CLASS.unknown)}>
      {name === "critical" && <span aria-hidden="true" className="mr-1 h-1.5 w-1.5 animate-pulse bg-crit" />}
      {name}
    </span>
  );
}

export function OutcomeChip({ outcome }: { outcome: CoverageOutcome }) {
  return <StatusBadge status={outcome} />;
}

export function Tag({ children, mono }: { children: ReactNode; mono?: boolean }) {
  return (
    <span className={cn("inline-flex items-center border border-line bg-black/20 px-1.5 py-0.5 text-[11px] text-muted", mono && "font-mono")}>
      {children}
    </span>
  );
}

export function Button({ children, onClick, variant = "default", disabled, title, ariaLabel, glitch }: {
  children?: ReactNode; onClick?: () => void; variant?: "default" | "primary" | "ghost" | "danger"; disabled?: boolean;
  title?: string; ariaLabel?: string; glitch?: string;
}) {
  return (
    <AeButton variant={variant} onClick={onClick} disabled={disabled} title={title} aria-label={ariaLabel} glitch={glitch}>
      {children}
    </AeButton>
  );
}

export function Loading({ label }: { label?: string }) {
  return <AsciiLoader label={label} />;
}

export function ErrorBox({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : String(error);
  return <SnarkyError error={error}>{message.startsWith("401") && <TokenForm />}</SnarkyError>;
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
      <input name="token" type="password" autoComplete="off" placeholder="hub token (WF_HUB_TOKEN)" aria-label="Hub token"
        className="flex-1 border border-line bg-black/40 px-3 py-1.5 font-mono text-ink outline-none focus:border-cyan" />
      <button type="submit" className="border border-cyan bg-cyan/10 px-3 py-1.5 font-mono text-xs uppercase text-cyan">auth</button>
    </form>
  );
}

export function Empty({ children, quipKey = "empty" }: { children?: ReactNode; quipKey?: string }) {
  return <SnarkyEmpty quipKey={quipKey}>{children}</SnarkyEmpty>;
}

export function PageHeader({ title, children, actions, kicker }: { title: string; children?: ReactNode; actions?: ReactNode; kicker?: string }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
      <div>
        <div className="font-mono text-[10px] uppercase tracking-[0.3em] text-cyan/80">{kicker ?? "watchfloor"} //</div>
        <h1 className="mt-1 text-2xl font-semibold tracking-tight">{title}</h1>
        {children && <p className="mt-1.5 max-w-3xl text-sm text-muted">{children}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}
