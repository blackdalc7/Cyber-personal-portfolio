import * as Dialog from "@radix-ui/react-dialog";
import { AnimatePresence, motion } from "motion/react";
import { useCallback, useEffect, useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent } from "react";
import { cn } from "../lib/cn";
import { complete, parseCommand } from "../lib/logic";
import { HoldToConfirm } from "./HoldToConfirm";

export type LineKind = "ok" | "error" | "info" | "warn" | "input";
export interface TermLine {
  kind: LineKind;
  text: string;
}

export interface ConfirmStep {
  label: string;
  /** Shown above the button, e.g. "This asks 02 for human approval." */
  warning?: string;
  duration?: number;
  tone?: "crimson" | "cyan" | "amber";
  run: () => Promise<TermLine[]> | TermLine[];
}

export type CommandResult = TermLine[] | { lines?: TermLine[]; confirm?: ConfirmStep; navigate?: string; close?: boolean };

export interface CommandContext {
  navigate: (to: string) => void;
  print: (lines: TermLine[]) => void;
}

export interface TerminalCommand {
  name: string;
  usage?: string;
  description: string;
  /** Values offered for Tab completion of the first argument. */
  complete?: () => string[];
  run: (args: string[], flags: Record<string, string | true>, ctx: CommandContext) => Promise<CommandResult> | CommandResult;
}

export const ok = (text: string): TermLine => ({ kind: "ok", text });
export const err = (text: string): TermLine => ({ kind: "error", text });
export const info = (text: string): TermLine => ({ kind: "info", text });
export const warn = (text: string): TermLine => ({ kind: "warn", text });

const LINE_CLASS: Record<LineKind, string> = {
  ok: "text-green", error: "text-crimson", info: "text-ink/80", warn: "text-amber", input: "text-cyan",
};

function builtins(all: () => TerminalCommand[], clear: () => void, user: string): TerminalCommand[] {
  return [
    { name: "help", description: "list commands", run: () => all().map((c) => info(`${`/${c.name}`.padEnd(14)} ${c.usage ? `${c.usage}  ` : ""}${c.description}`)) },
    { name: "clear", description: "clear the screen", run: () => { clear(); return []; } },
    { name: "whoami", description: "print the current user", run: () => [ok(user), info("groups: soc, coffee-dependants")] },
    { name: "exit", description: "close the terminal", run: () => ({ close: true }) },
    { name: "sudo", description: "elevate privileges", run: () => [err(`${user} is not in the sudoers file. This incident will be reported.`), info("(to the SOC. which is you. awkward.)")] },
    { name: "rm", description: "remove files", run: (a) => (a.join(" ").includes("-rf") ? [err("rm: refusing to remove '/': this is a SOC, not a startup")] : [err("rm: read-only console")]) },
    { name: "hack", description: "hack the planet", run: () => [ok("HACK THE PLANET!"), info("tip: the real hack is ↑ ↑ ↓ ↓ ← → ← → B A")] },
  ];
}

/**
 * Ctrl/Cmd+K terminal. Typed commands are the primary navigation; history (↑/↓), Tab completion, async commands
 * and inline hold-to-confirm steps are built in. Unknown input falls back to fuzzy "jump to" suggestions.
 */
export function TerminalPalette({ open, onOpenChange, commands, suggestions = [], navigate, host = "watchfloor", user = "analyst", motd }: {
  open: boolean; onOpenChange: (open: boolean) => void; commands: TerminalCommand[];
  suggestions?: { label: string; hint?: string; to: string }[]; navigate: (to: string) => void;
  host?: string; user?: string; motd?: string[];
}) {
  const [lines, setLines] = useState<TermLine[]>([]);
  const [input, setInput] = useState("");
  const [history, setHistory] = useState<string[]>([]);
  const [hIdx, setHIdx] = useState(-1);
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState<ConfirmStep | null>(null);
  const [sel, setSel] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const scroller = useRef<HTMLDivElement>(null);

  const clear = useCallback(() => setLines([]), []);
  const all = useMemo(() => {
    const list: TerminalCommand[] = [];
    const get = () => list;
    list.push(...commands, ...builtins(get, clear, user).filter((b) => !commands.some((c) => c.name === b.name)));
    return list;
  }, [commands, clear, user]);

  useEffect(() => {
    if (open && !lines.length && motd) setLines(motd.map(info));
    if (open) window.setTimeout(() => inputRef.current?.focus(), 0);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);
  useEffect(() => {
    scroller.current?.scrollTo({ top: scroller.current.scrollHeight });
  }, [lines, confirm]);

  const matches = useMemo(() => {
    const q = input.trim().toLowerCase();
    if (!q || q.startsWith("/")) return [];
    return suggestions.filter((s) => `${s.label} ${s.hint ?? ""}`.toLowerCase().includes(q)).slice(0, 8);
  }, [input, suggestions]);
  useEffect(() => setSel(0), [input]);

  const print = useCallback((l: TermLine[]) => setLines((x) => [...x, ...l].slice(-400)), []);
  const prompt = `${user}@${host} ~ %`;

  const exec = async (raw: string) => {
    const line = raw.trim();
    if (!line) return;
    setHistory((h) => [line, ...h.filter((x) => x !== line)].slice(0, 50));
    setHIdx(-1);
    setInput("");
    print([{ kind: "input", text: `${prompt} ${line}` }]);
    const { name, args, flags } = parseCommand(line);
    const cmd = all.find((c) => c.name === name);
    if (!cmd) {
      print([err(`zsh: command not found: ${name}`), info("try /help. or ↑ ↑ ↓ ↓ ← → ← → B A. no reason.")]);
      return;
    }
    setBusy(true);
    try {
      const res = await cmd.run(args, flags, { navigate, print });
      if (Array.isArray(res)) print(res);
      else {
        if (res.lines) print(res.lines);
        if (res.confirm) setConfirm(res.confirm);
        if (res.navigate) { navigate(res.navigate); onOpenChange(false); }
        if (res.close) onOpenChange(false);
      }
    } catch (e) {
      print([err(e instanceof Error ? e.message : String(e))]);
    } finally {
      setBusy(false);
    }
  };

  const onKey = (e: ReactKeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") {
      e.preventDefault();
      if (matches[sel] && !input.startsWith("/")) { navigate(matches[sel].to); onOpenChange(false); setInput(""); }
      else void exec(input.startsWith("/") || all.some((c) => c.name === parseCommand(input).name) ? input : `/${input}`);
    } else if (e.key === "Tab") {
      e.preventDefault();
      const { name, args } = parseCommand(input);
      if (!args.length && !input.endsWith(" ")) {
        const r = complete(input.startsWith("/") ? input : `/${input}`, all.map((c) => c.name));
        if (r.matches.length === 1) setInput(`/${r.matches[0]} `);
        else if (r.matches.length > 1) { setInput(r.completion); print([info(r.matches.map((m) => `/${m}`).join("   "))]); }
      } else {
        const cmd = all.find((c) => c.name === name);
        const opts = cmd?.complete?.() ?? [];
        const r = complete(args[0] ?? "", opts);
        if (r.matches.length === 1) setInput(`/${name} ${r.matches[0]} `);
        else if (r.matches.length > 1) { setInput(`/${name} ${r.completion}`); print([info(r.matches.join("   "))]); }
      }
    } else if (e.key === "ArrowUp" && !matches.length) {
      e.preventDefault();
      const i = Math.min(hIdx + 1, history.length - 1);
      if (history[i] !== undefined) { setHIdx(i); setInput(history[i]); }
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      if (matches.length) setSel((s) => Math.min(s + 1, matches.length - 1));
      else { const i = hIdx - 1; setHIdx(Math.max(i, -1)); setInput(i >= 0 ? history[i] : ""); }
    } else if (e.key === "ArrowUp" && matches.length) {
      e.preventDefault();
      setSel((s) => Math.max(s - 1, 0));
    } else if (e.key === "l" && e.ctrlKey) {
      e.preventDefault();
      clear();
    }
  };

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <AnimatePresence>
        {open && (
          <Dialog.Portal forceMount>
            <Dialog.Overlay asChild>
              <motion.div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-[2px]" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} />
            </Dialog.Overlay>
            <Dialog.Content asChild aria-describedby={undefined}>
              <motion.div initial={{ opacity: 0, y: -12, scale: 0.98 }} animate={{ opacity: 1, y: 0, scale: 1 }} exit={{ opacity: 0, y: -8 }}
                transition={{ type: "spring", stiffness: 420, damping: 32 }}
                className="ae-glass ae-scanlines fixed left-1/2 top-[10vh] z-50 w-[min(94vw,760px)] -translate-x-1/2 shadow-[0_30px_80px_-20px_rgb(0_0_0/0.8)]">
                <div className="flex items-center gap-2 border-b border-line px-3 py-2">
                  <span className="h-2.5 w-2.5 rounded-full bg-crimson/80" /><span className="h-2.5 w-2.5 rounded-full bg-amber/80" /><span className="h-2.5 w-2.5 rounded-full bg-green/80" />
                  <Dialog.Title className="ml-2 font-mono text-[11px] text-muted">zsh · {user}@{host}</Dialog.Title>
                  <span className="ml-auto font-mono text-[10px] text-muted">tab completes · ↑ history · esc closes</span>
                </div>
                <div ref={scroller} className="max-h-[46vh] min-h-[160px] overflow-y-auto px-4 py-3 font-mono text-[12.5px] leading-relaxed">
                  {lines.map((l, i) => <div key={i} className={cn("whitespace-pre-wrap break-words", LINE_CLASS[l.kind])}>{l.text}</div>)}
                  {confirm && (
                    <div className="my-2 border border-line bg-black/30 p-3">
                      {confirm.warning && <p className="mb-2 text-amber">{confirm.warning}</p>}
                      <div className="flex flex-wrap items-center gap-2">
                        <HoldToConfirm label={confirm.label} duration={confirm.duration} tone={confirm.tone}
                          onConfirm={async () => { const step = confirm; setConfirm(null); print(await step.run()); }} />
                        <button type="button" className="font-mono text-xs text-muted hover:text-ink" onClick={() => { setConfirm(null); print([warn("aborted. the host lives another day.")]); }}>abort</button>
                      </div>
                    </div>
                  )}
                  <div className="flex items-center gap-2">
                    <span className="shrink-0 text-green">{prompt}</span>
                    <input ref={inputRef} value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={onKey}
                      disabled={busy} spellCheck={false} autoComplete="off" aria-label="Terminal command"
                      className="min-w-0 flex-1 bg-transparent text-ink caret-green outline-none focus-visible:shadow-none focus-visible:outline-none" placeholder={busy ? "running…" : "/help"} />
                  </div>
                </div>
                {matches.length > 0 && (
                  <ul className="border-t border-line p-1" role="listbox" aria-label="Jump to">
                    {matches.map((m, i) => (
                      <li key={m.to} role="option" aria-selected={i === sel}>
                        <button type="button" onMouseEnter={() => setSel(i)} onClick={() => { navigate(m.to); onOpenChange(false); setInput(""); }}
                          className={cn("flex w-full items-center gap-3 px-3 py-1.5 text-left font-mono text-xs", i === sel ? "bg-cyan/10 text-cyan" : "text-ink/80")}>
                          <span className="text-muted">cd</span><span className="flex-1 truncate">{m.label}</span><span className="text-muted">{m.hint}</span>
                        </button>
                      </li>
                    ))}
                  </ul>
                )}
              </motion.div>
            </Dialog.Content>
          </Dialog.Portal>
        )}
      </AnimatePresence>
    </Dialog.Root>
  );
}

/** Global Ctrl/Cmd+K and "/" (when not typing) toggle for the terminal. */
export function useTerminalHotkey(setOpen: (fn: (o: boolean) => boolean) => void): void {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const typing = (e.target as HTMLElement | null)?.closest?.("input, textarea, select, [contenteditable]");
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); setOpen((o) => !o); }
      else if (e.key === "/" && !typing) { e.preventDefault(); setOpen(() => true); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [setOpen]);
}

