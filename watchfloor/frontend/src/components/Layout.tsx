import {
  Kbd, SettingsSheet, TerminalPalette, analystStress, cn, err, info, ok, useModes,
  useTerminalHotkey, warn, ISOLATION_QUIPS, type TerminalCommand,
} from "@portfolio/aegis-ui";
import { useEffect, useMemo, useState, type ReactNode } from "react";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import { useLoad, useSource } from "../lib/data";
import { fmtTime } from "../lib/logic";

/** The page index. `key` is the single-key shortcut, `cmd` the name used by the command line's /cd. */
const NAV = [
  { to: "/", label: "Watch floor", key: "1", cmd: "floor" },
  { to: "/scenarios", label: "Scenarios", key: "2", cmd: "scenarios" },
  { to: "/incidents", label: "Incidents", key: "3", cmd: "incidents" },
  { to: "/coverage", label: "Coverage", key: "4", cmd: "coverage" },
  { to: "/exposure", label: "Exposure", key: "5", cmd: "exposure" },
  { to: "/rules", label: "Rules", key: "6", cmd: "rules" },
  { to: "/analyst", label: "Analyst engine", key: "7", cmd: "analyst" },
];

const REPO_URL = "https://github.com/blackdalc7/Cyber-personal-portfolio";

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

/**
 * Page shell: a masthead column with the wordmark and a numbered page index, a quiet top bar with the command line
 * (Ctrl K or /), the data mode and settings, then the page itself. Number keys 1 to 7 jump between pages.
 */
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
          : [warn(`0 findings for ${t}. It either did not happen or was not detected. Check /cd coverage.`)];
      } },
    { name: "isolate", usage: "<host> [--reason text]", description: "ask 02 for a human-approved isolation", complete: () => hosts,
      run: (a, flags) => {
        const host = a[0];
        if (!host || !/^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$/.test(host)) return [err("usage: /isolate <host> --reason \"why\"")];
        const reason = typeof flags.reason === "string" ? flags.reason : "requested from the console";
        return {
          lines: [warn(ISOLATION_QUIPS[0])],
          confirm: {
            label: `isolate ${host}`, tone: "bad", duration: 1800,
            warning: src.mode === "replay"
              ? "Replay demo: this simulates the request. Nothing leaves your browser."
              : "This asks the SOAR bot (02) to post an approval card. A human approver must still click Approve in Slack or Discord.",
            run: async () => {
              try {
                const r = await src.requestIsolation(host, reason);
                return r.status === "simulated"
                  ? [ok(`[simulated] approval card for ${host} would now be waiting in Slack.`), info("Replay demo: no request left this browser.")]
                  : [ok(`approval requested: ${r.soar?.incident_id ?? "incident opened"} (${r.soar?.status ?? "awaiting approval"})`),
                    info("A second analyst must approve it in Slack or Discord (separation of duties).")];
              } catch (e) {
                return [err(`request failed: ${e instanceof Error ? e.message : String(e)}`)];
              }
            },
          },
        };
      } },
    { name: "workload", description: "analyst workload index", run: () => {
      const k = summary.data?.kpis;
      const r = analystStress({ alertsPerHour: k?.findings ?? 0, openIncidents: k?.open_incidents ?? 0, mttaSeconds: k?.mtta_s });
      return [info(`analyst workload: ${r.score}/100 (${r.label})`), info(r.quip)];
    } },
    { name: "theme", usage: "dark|light", description: "switch theme", complete: () => ["dark", "light"],
      run: (a) => { setTheme(a[0] === "light" ? "light" : "dark"); return [ok(`theme: ${a[0] === "light" ? "light" : "dark"}`)]; } },
    { name: "phosphor", description: "ten-second green-screen preview (cosmetic)", run: () => { phosphor(); return { close: true }; } },
  ], [src, scenarios.data, incidents.data, hosts, summary.data, setTheme, phosphor]);

  const suggestions = useMemo(() => [
    ...NAV.map((n) => ({ label: n.label, hint: "page", to: n.to })),
    ...(scenarios.data ?? []).map((s) => ({ label: `play ${s.title}`, hint: "scenario", to: `/scenarios/${s.id}` })),
    ...(incidents.data ?? []).map((i) => ({ label: `${i.id} ${i.title}`, hint: i.host ?? "incident", to: `/incidents/${encodeURIComponent(i.id)}` })),
  ], [scenarios.data, incidents.data]);

  const here = NAV.find((n) => (n.to === "/" ? location.pathname === "/" : location.pathname.startsWith(n.to)));

  return (
    <div className="flex h-full">
      <aside className="hidden w-56 shrink-0 flex-col border-r border-line px-6 py-7 md:flex">
        <a href="#/" className="block">
          <span className="block font-serif text-[1.625rem] font-semibold leading-none text-ink">Watchfloor</span>
          <span className="mt-2 block text-[12px] leading-snug text-muted">Detection and response console for a home security lab</span>
        </a>
        <nav className="mt-10" aria-label="Main">
          <ol className="space-y-1.5">
            {NAV.map(({ to, label, key }) => (
              <li key={to}>
                <NavLink to={to} end={to === "/"} title={`${label} (press ${key})`}
                  className={({ isActive }) => cn("flex items-baseline gap-3 py-0.5 text-[14px]",
                    isActive ? "text-ink underline decoration-accent decoration-2 underline-offset-[6px]" : "text-muted hover:text-ink")}>
                  <span className="w-5 font-mono text-[11px] text-muted" aria-hidden="true">0{key}</span>{label}
                </NavLink>
              </li>
            ))}
          </ol>
        </nav>
        <div className="mt-auto space-y-3 border-t border-line pt-4 text-[12px] text-muted">
          <p>Events normalised to OCSF 1.4 and queried with DuckDB.</p>
          <a href={REPO_URL} className="block text-accent hover:underline">Source and test results on GitHub</a>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center gap-4 border-b border-line px-4 py-2.5 md:px-10">
          <nav className="flex gap-3 overflow-x-auto md:hidden" aria-label="Main (mobile)">
            {NAV.map(({ to, label }) => (
              <NavLink key={to} to={to} end={to === "/"}
                className={({ isActive }) => cn("whitespace-nowrap text-[13px]", isActive ? "text-ink underline decoration-accent decoration-2 underline-offset-4" : "text-muted")}>
                {label}
              </NavLink>
            ))}
          </nav>
          <button type="button" onClick={() => setTerm(true)} aria-label="Open terminal"
            className="hidden min-w-0 items-center gap-3 text-left text-[13px] text-muted hover:text-ink sm:flex">
            <span>Command line</span>
            <span className="font-mono text-[12px]">~/{here?.cmd ?? "floor"}</span>
            <span className="flex gap-1"><Kbd>Ctrl K</Kbd><Kbd>/</Kbd></span>
          </button>
          <span className="ml-auto" />
          <ModeBadge mode={src.mode} />
          <SettingsSheet theme={theme} onTheme={setTheme} version="Watchfloor 1.0" />
        </header>
        <main className="min-h-0 flex-1 overflow-y-auto px-4 py-8 md:px-10 md:py-10">
          <div className="mx-auto max-w-[1280px]">{children}</div>
        </main>
      </div>
      <TerminalPalette open={term} onOpenChange={setTerm} commands={commands} suggestions={suggestions} navigate={navigate}
        host="watchfloor" motd={[
          "Watchfloor command line. Type /help for commands, or start typing a page or incident to jump to it.",
          src.mode === "replay" ? "Mode: replay demo. Recorded data; actions are simulated." : "Mode: live. Actions go to the SOAR bot (02) and still need a human approval.",
        ]} />
    </div>
  );
}

/** Data provenance, always visible: recorded replay data or the live lake. */
function ModeBadge({ mode }: { mode: "live" | "replay" }) {
  return mode === "live" ? (
    <span className="flex items-center gap-1.5 font-mono text-[11px] text-good">
      <span className="ae-live h-1.5 w-1.5 bg-good" aria-hidden="true" /> LIVE
    </span>
  ) : (
    <span className="border border-warn px-2 font-mono text-[11px] leading-5 text-warn"
      title="Recorded datasets from the portfolio projects. Run the stack locally for live data.">REPLAY DEMO</span>
  );
}
