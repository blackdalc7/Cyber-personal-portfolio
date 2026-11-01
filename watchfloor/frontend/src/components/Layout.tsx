import {
  GlitchText, Kbd, SettingsSheet, TerminalIcon, TerminalPalette, analystStress, cn, err, info, ok, useModes,
  useTerminalHotkey, warn, ISOLATION_QUIPS, type TerminalCommand,
} from "@portfolio/aegis-ui";
import { Activity, Bot, FileCode2, Grid3x3, Network, PlayCircle, ShieldAlert } from "lucide-react";
import { useEffect, useMemo, useState, type ReactNode } from "react";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import { useLoad, useSource } from "../lib/data";
import { fmtTime } from "../lib/logic";

const NAV = [
  { to: "/", label: "Watch floor", icon: Activity, key: "1", cmd: "floor" },
  { to: "/scenarios", label: "Scenarios", icon: PlayCircle, key: "2", cmd: "scenarios" },
  { to: "/incidents", label: "Incidents", icon: ShieldAlert, key: "3", cmd: "incidents" },
  { to: "/coverage", label: "Coverage", icon: Grid3x3, key: "4", cmd: "coverage" },
  { to: "/exposure", label: "Exposure", icon: Network, key: "5", cmd: "exposure" },
  { to: "/rules", label: "Rules", icon: FileCode2, key: "6", cmd: "rules" },
  { to: "/analyst", label: "Analyst engine", icon: Bot, key: "7", cmd: "analyst" },
];

function useTheme() {
  const [theme, setTheme] = useState<"dark" | "light">(() => {
    try {
      return (localStorage.getItem("wf.theme") as "dark" | "light") || "dark";
    } catch {
      return "dark";
    }
  });
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem("wf.theme", theme);
    } catch {
      /* storage blocked: the theme still applies for this visit */
    }
    window.dispatchEvent(new Event("wf-theme"));
  }, [theme]);
  return [theme, setTheme] as const;
}

/** Terminal-first shell: a slim icon rail for mouse users, but the zsh palette (Ctrl K or /) is the real navigation. */
export function Layout({ children }: { children: ReactNode }) {
  const src = useSource();
  const [theme, setTheme] = useTheme();
  const [term, setTerm] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();
  const { phosphor } = useModes();
  const incidents = useLoad((s) => s.incidents());
  const scenarios = useLoad((s) => s.scenarios());
  const summary = useLoad((s) => s.summary());

  useTerminalHotkey(setTerm);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.target as HTMLElement).closest("input, textarea, select") || e.ctrlKey || e.metaKey || e.altKey || term) return;
      const item = NAV.find((n) => n.key === e.key);
      if (item) navigate(item.to);
      if (e.key === "t") setTheme((t) => (t === "dark" ? "light" : "dark"));
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [navigate, setTheme, term]);

  const hosts = useMemo(() => [...new Set([
    ...(incidents.data ?? []).map((i) => i.host).filter((h): h is string => !!h),
    ...(scenarios.data ?? []).flatMap((s) => s.hosts),
  ])].sort(), [incidents.data, scenarios.data]);

  const commands = useMemo<TerminalCommand[]>(() => [
    { name: "cd", usage: "<page>", description: "go to a page", complete: () => NAV.map((n) => n.cmd),
      run: (a) => {
        const n = NAV.find((x) => x.cmd === (a[0] ?? "").replace(/^\//, "") || x.to === a[0]);
        return n ? { navigate: n.to } : [err(`cd: no such page: ${a[0] ?? ""}`), info(`pages: ${NAV.map((x) => x.cmd).join(" ")}`)];
      } },
    { name: "ls", usage: "incidents|scenarios|hosts", description: "list things", complete: () => ["incidents", "scenarios", "hosts"],
      run: (a) => {
        if (a[0] === "scenarios") return (scenarios.data ?? []).map((s) => info(`${s.id.padEnd(34)} ${s.stages.length} stages`));
        if (a[0] === "hosts") return hosts.map((h) => info(h));
        return (incidents.data ?? []).map((i) => info(`${i.id}  ${i.status.padEnd(18)} ${(i.host ?? "-").padEnd(10)} ${i.title.slice(0, 50)}`));
      } },
    { name: "play", usage: "<scenario>", description: "replay an attack and score it", complete: () => (scenarios.data ?? []).map((s) => s.id),
      run: (a) => {
        const sc = (scenarios.data ?? []).find((s) => s.id === a[0]) ?? (scenarios.data ?? [])[0];
        return sc ? { navigate: `/scenarios/${sc.id}` } : [err("no scenarios loaded")];
      } },
    { name: "incident", usage: "<id>", description: "open an incident", complete: () => (incidents.data ?? []).map((i) => i.id),
      run: (a) => {
        const inc = (incidents.data ?? []).find((i) => i.id.toLowerCase().startsWith((a[0] ?? "").toLowerCase()));
        return inc ? { navigate: `/incidents/${encodeURIComponent(inc.id)}` } : [err(`incident not found: ${a[0] ?? ""}`)];
      } },
    { name: "hunt", usage: "<T-id>", description: "findings for an ATT&CK technique",
      run: async (a) => {
        const t = (a[0] ?? "").toUpperCase();
        if (!/^T\d{4}(\.\d{3})?$/.test(t)) return [err("usage: /hunt T1110.001")];
        const rows = (await src.findings()).filter((f) => f.techniques.some((x) => x === t || x.split(".")[0] === t || t.split(".")[0] === x));
        return rows.length
          ? [ok(`${rows.length} finding(s) for ${t}`), ...rows.slice(0, 15).map((r) => info(`${fmtTime(r.time)} ${(r.hostname ?? "-").padEnd(10)} ${r.finding_title ?? ""}`))]
          : [warn(`0 findings for ${t}. Either nobody did it, or nobody saw it. Check /cd coverage.`)];
      } },
    { name: "isolate", usage: "<host> [--reason text]", description: "ask 02 for a human-approved isolation", complete: () => hosts,
      run: (a, flags) => {
        const host = a[0];
        if (!host || !/^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$/.test(host)) return [err("usage: /isolate <host> --reason \"why\"")];
        const reason = typeof flags.reason === "string" ? flags.reason : "requested from the console";
        return {
          lines: [warn(ISOLATION_QUIPS[host.length % ISOLATION_QUIPS.length])],
          confirm: {
            label: `isolate ${host}`, tone: "crimson", duration: 1800,
            warning: src.mode === "replay"
              ? "Replay demo: this simulates the request. Nothing leaves your browser."
              : "This asks the SOAR bot (02) to post an approval card. A human approver must still click Approve in Slack or Discord.",
            run: async () => {
              try {
                const r = await src.requestIsolation(host, reason);
                return r.status === "simulated"
                  ? [ok(`[simulated] approval card for ${host} would now be waiting in Slack.`), info("no packets were harmed in the making of this demo.")]
                  : [ok(`approval requested: ${r.soar?.incident_id ?? "incident opened"} (${r.soar?.status ?? "awaiting approval"})`),
                    info("now go and find an approver who is not you. separation of duties.")];
              } catch (e) {
                return [err(`request failed: ${e instanceof Error ? e.message : String(e)}`)];
              }
            },
          },
        };
      } },
    { name: "stress", description: "how the analyst is doing", run: () => {
      const k = summary.data?.kpis;
      const r = analystStress({ alertsPerHour: k?.findings ?? 0, openIncidents: k?.open_incidents ?? 0, mttaSeconds: k?.mtta_s });
      return [info(`analyst stress index: ${r.score}/100 (${r.label})`), info(`caffeine required: ${"☕".repeat(r.cups) || "none, suspiciously"}`), info(r.quip)];
    } },
    { name: "theme", usage: "dark|light", description: "switch theme", complete: () => ["dark", "light"],
      run: (a) => { setTheme(a[0] === "light" ? "light" : "dark"); return [ok(`theme: ${a[0] === "light" ? "light" : "dark"}`)]; } },
    { name: "phosphor", description: "1993 called", run: () => { phosphor(); return { close: true }; } },
  ], [src, scenarios.data, incidents.data, hosts, summary.data, setTheme, phosphor]);

  const suggestions = useMemo(() => [
    ...NAV.map((n) => ({ label: n.label, hint: "page", to: n.to })),
    ...(scenarios.data ?? []).map((s) => ({ label: `play ${s.title}`, hint: "scenario", to: `/scenarios/${s.id}` })),
    ...(incidents.data ?? []).map((i) => ({ label: `${i.id} ${i.title}`, hint: i.host ?? "incident", to: `/incidents/${encodeURIComponent(i.id)}` })),
  ], [scenarios.data, incidents.data]);

  const here = NAV.find((n) => (n.to === "/" ? location.pathname === "/" : location.pathname.startsWith(n.to)));

  return (
    <div className="flex h-full">
      <aside className="hidden w-14 shrink-0 flex-col items-center border-r border-line bg-black/30 py-3 backdrop-blur md:flex">
        <svg viewBox="0 0 32 32" className="mb-4 h-7 w-7" aria-label="Watchfloor">
          <rect x="0.5" y="0.5" width="31" height="31" fill="none" className="stroke-line" />
          <path d="M6 22l6-8 5 5 9-11" className="stroke-cyan" strokeWidth="2.5" fill="none" strokeLinecap="square" />
        </svg>
        <nav className="flex flex-1 flex-col gap-1" aria-label="Main">
          {NAV.map(({ to, label, icon: Icon, key }) => (
            <NavLink key={to} to={to} end={to === "/"} title={`${label} (${key})`} aria-label={label}
              className={({ isActive }) => cn("group relative flex h-9 w-9 items-center justify-center border transition",
                isActive ? "border-cyan/60 bg-cyan/10 text-cyan shadow-[var(--ae-glow)]" : "border-transparent text-muted hover:border-line hover:text-ink")}>
              <Icon className="h-4 w-4" aria-hidden="true" />
              <span className="pointer-events-none absolute left-11 z-40 hidden whitespace-nowrap border border-line bg-panel-solid px-2 py-1 font-mono text-[10px] text-ink group-hover:block">
                {label} <span className="text-muted">[{key}]</span>
              </span>
            </NavLink>
          ))}
        </nav>
        <span className="font-mono text-[9px] text-muted [writing-mode:vertical-rl]">OCSF 1.4 · DUCKDB</span>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center gap-3 border-b border-line bg-black/30 px-4 py-2 backdrop-blur">
          <nav className="flex gap-0.5 overflow-x-auto md:hidden" aria-label="Main (mobile)">
            {NAV.map(({ to, icon: Icon, label }) => (
              <NavLink key={to} to={to} end={to === "/"} aria-label={label}
                className={({ isActive }) => cn("p-2", isActive ? "text-cyan" : "text-muted")}>
                <Icon className="h-4 w-4" />
              </NavLink>
            ))}
          </nav>
          <button type="button" onClick={() => setTerm(true)} aria-label="Open terminal"
            className="group flex min-w-0 flex-1 items-center gap-2 border border-line bg-black/40 px-3 py-1.5 text-left font-mono text-xs hover:border-cyan/50 md:max-w-xl">
            <TerminalIcon className="h-3.5 w-3.5 shrink-0 text-green" />
            <span className="truncate text-green">analyst@watchfloor</span>
            <span className="hidden truncate text-muted sm:inline">~/{here?.cmd ?? "floor"} %</span>
            <span className="ae-caret truncate text-muted/70">type /help</span>
            <span className="ml-auto hidden gap-1 sm:flex"><Kbd>Ctrl K</Kbd><Kbd>/</Kbd></span>
          </button>
          <ModeBadge mode={src.mode} />
          <SettingsSheet theme={theme} onTheme={setTheme} version="watchfloor v1.0 · built in a student flat, tested in a lab" />
        </header>
        <main className="min-h-0 flex-1 overflow-y-auto p-4 md:p-6">{children}</main>
      </div>
      <TerminalPalette open={term} onOpenChange={setTerm} commands={commands} suggestions={suggestions} navigate={navigate}
        host="watchfloor" motd={[
          "Watchfloor terminal. Type /help for commands, or just start typing to jump somewhere.",
          src.mode === "replay" ? "Mode: REPLAY DEMO. Recorded data, actions are simulated." : "Mode: LIVE. Actions go to 02 and still need a human approval.",
        ]} />
    </div>
  );
}

function ModeBadge({ mode }: { mode: "live" | "replay" }) {
  return mode === "live" ? (
    <span className="flex items-center gap-1.5 border border-green/50 bg-green/10 px-2 py-1 font-mono text-[10px] font-semibold tracking-widest text-green">
      <span className="ae-live h-1.5 w-1.5 bg-green" /> LIVE
    </span>
  ) : (
    <span className="border border-amber/50 bg-amber/10 px-2 py-1 font-mono text-[10px] font-semibold tracking-widest text-amber"
      title="Recorded datasets from the portfolio projects. Run the stack locally for live data.">
      <GlitchText text="REPLAY DEMO" />
    </span>
  );
}
