// Pure, framework-free logic behind the components, so it can be unit-tested without a DOM.

export const HEX = "0123456789ABCDEF";
export const GLYPHS = "!<>-_\\/[]{}=+*^?#$%&@0123456789ABCDEF";

/** Deterministic PRNG (mulberry32) so tests and SSR-free snapshots are stable. */
export function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * One frame of a left-to-right reveal: characters before `progress * length` are final, the rest are random
 * glyphs. Spaces stay spaces so the word shapes are readable while scrambling.
 */
export function scrambleFrame(target: string, progress: number, rand: () => number, alphabet = GLYPHS): string {
  const p = Math.min(Math.max(progress, 0), 1);
  const fixed = Math.floor(target.length * p);
  let out = "";
  for (let i = 0; i < target.length; i++) {
    const ch = target[i];
    out += i < fixed || ch === " " || ch === "\n" ? ch : alphabet[Math.floor(rand() * alphabet.length)];
  }
  return out;
}

export const KONAMI = ["ArrowUp", "ArrowUp", "ArrowDown", "ArrowDown", "ArrowLeft", "ArrowRight", "ArrowLeft", "ArrowRight", "b", "a"];

/** Feed keys one at a time; returns the new match position, and `done` when the whole sequence was typed. */
export function konamiStep(position: number, key: string, sequence = KONAMI): { position: number; done: boolean } {
  const k = key.length === 1 ? key.toLowerCase() : key;
  if (k === sequence[position]) {
    const next = position + 1;
    return next === sequence.length ? { position: 0, done: true } : { position: next, done: false };
  }
  return { position: k === sequence[0] ? 1 : 0, done: false };
}

export interface StressInput {
  /** Alerts (or findings) arriving per hour right now. */
  alertsPerHour: number;
  /** Open incidents waiting on a human. */
  openIncidents: number;
  /** Critical findings in the window. */
  critical?: number;
  /** Mean time to approve, seconds (slow approvals mean a stressed queue). */
  mttaSeconds?: number | null;
}

export interface StressReading {
  score: number; // 0..100
  cups: number; // legacy 0..6 scale kept for older callers
  level: "zen" | "caffeinated" | "jittery" | "on-fire" | "sleeping-under-desk";
  label: string;
  quip: string;
}

const LEVELS: { max: number; level: StressReading["level"]; label: string; quip: string }[] = [
  { max: 15, level: "zen", label: "Low", quip: "Queue is quiet. Use the time for rule tuning." },
  { max: 40, level: "caffeinated", label: "Moderate", quip: "Normal working load." },
  { max: 65, level: "jittery", label: "Elevated", quip: "Queue is growing. Prioritise by severity." },
  { max: 85, level: "on-fire", label: "High", quip: "Alerts are arriving faster than they are closed." },
  { max: 101, level: "sleeping-under-desk", label: "Critical", quip: "Escalate to the on-call lead." },
];

/**
 * Analyst workload index: a saturating blend of alert rate, open incidents,
 * critical findings and approval latency, each normalised so one runaway input cannot pin the gauge alone.
 */
export function analystStress(input: StressInput): StressReading {
  const sat = (x: number, k: number) => 1 - Math.exp(-Math.max(0, x) / k);
  const score = Math.round(
    100 * (0.4 * sat(input.alertsPerHour, 40) + 0.3 * sat(input.openIncidents, 3) +
      0.2 * sat(input.critical ?? 0, 5) + 0.1 * sat((input.mttaSeconds ?? 0) / 60, 15)),
  );
  const band = LEVELS.find((l) => score < l.max) ?? LEVELS[LEVELS.length - 1];
  return { score, cups: Math.min(6, Math.round(score / 16)), level: band.level, label: band.label, quip: band.quip };
}

const EMPTY_MESSAGES = [
  "No records in this view yet.",
  "Nothing has been recorded for this view.",
  "This view is empty for the selected data.",
];

/**
 * A stable empty-state message for a given key, so the same view always shows the same sentence.
 * (Kept as `quipFor` for backwards compatibility with earlier consoles.)
 */
export function quipFor(key: string, messages = EMPTY_MESSAGES): string {
  let h = 0;
  for (let i = 0; i < key.length; i++) h = (h * 31 + key.charCodeAt(i)) | 0;
  return messages[Math.abs(h) % messages.length];
}

/** Plain guidance shown under an error, chosen by `quipFor(message, ERROR_QUIPS)`. */
export const ERROR_QUIPS = [
  "Check that the hub is running and reachable, then reload.",
  "The request did not complete. Reload to try again.",
  "If this persists, check the browser console and the hub logs.",
];

/** Status lines shown while an isolation request is being sent to the SOAR bot. */
export const ISOLATION_QUIPS = [
  "Requesting isolation. A human approver must still confirm it.",
  "Sending the isolation request to the SOAR bot.",
  "Isolation requested. Waiting for the approval card.",
];

/** Split a terminal command line into words, honouring single and double quotes. */
export function parseCommand(line: string): { name: string; args: string[]; flags: Record<string, string | true> } {
  const words: string[] = [];
  let cur = "";
  let quote: string | null = null;
  let had = false;
  for (const ch of line.trim()) {
    if (quote) {
      if (ch === quote) quote = null;
      else cur += ch;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
      had = true;
    } else if (/\s/.test(ch)) {
      if (cur || had) words.push(cur);
      cur = "";
      had = false;
    } else {
      cur += ch;
    }
  }
  if (cur || had) words.push(cur);
  const [first = "", ...rest] = words;
  const args: string[] = [];
  const flags: Record<string, string | true> = {};
  for (let i = 0; i < rest.length; i++) {
    const w = rest[i];
    if (w.startsWith("--")) {
      const [k, v] = w.slice(2).split("=", 2);
      if (v !== undefined) flags[k] = v;
      else if (rest[i + 1] !== undefined && !rest[i + 1].startsWith("--")) flags[k] = rest[++i];
      else flags[k] = true;
    } else {
      args.push(w);
    }
  }
  return { name: first.replace(/^\//, "").toLowerCase(), args, flags };
}

/** Longest common prefix of the candidates that start with `partial` (for Tab completion). */
export function complete(partial: string, candidates: string[]): { completion: string; matches: string[] } {
  const p = partial.replace(/^\//, "").toLowerCase();
  const matches = candidates.filter((c) => c.toLowerCase().startsWith(p)).sort();
  if (!matches.length) return { completion: partial, matches };
  let prefix = matches[0];
  for (const m of matches.slice(1)) {
    let i = 0;
    while (i < prefix.length && i < m.length && prefix[i].toLowerCase() === m[i].toLowerCase()) i++;
    prefix = prefix.slice(0, i);
  }
  return { completion: (partial.startsWith("/") ? "/" : "") + prefix, matches };
}

/** Classic hexdump line: offset, 16 bytes in hex, printable ASCII. */
export function hexdumpLine(offset: number, bytes: number[]): string {
  const hex = bytes.map((b) => b.toString(16).padStart(2, "0")).join(" ").padEnd(47, " ");
  const ascii = bytes.map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : ".")).join("");
  return `${offset.toString(16).padStart(8, "0")}  ${hex}  |${ascii}|`;
}

export const STATUS = {
  prevented: { label: "Prevented", glyph: "■", varName: "--ae-status-prevented" },
  detected: { label: "Detected", glyph: "●", varName: "--ae-status-detected" },
  missed: { label: "Missed", glyph: "✕", varName: "--ae-status-missed" },
  error: { label: "Error", glyph: "!", varName: "--ae-status-error" },
  drift: { label: "Drift", glyph: "~", varName: "--ae-status-drift" },
  remediated: { label: "Remediated", glyph: "✓", varName: "--ae-status-remediated" },
  telemetry_only: { label: "Telemetry only", glyph: "◐", varName: "--ae-status-telemetry" },
  skipped: { label: "Skipped", glyph: "–", varName: "--ae-status-skipped" },
} as const;

export type StatusName = keyof typeof STATUS;
