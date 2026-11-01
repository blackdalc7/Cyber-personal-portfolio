# @portfolio/aegis-ui

The shared design system for **Watchfloor** and **Driftwatch**: *Aegis* structure (zinc-950, 1px zinc-800 lines,
glass panels, functional colour only) with *Carbon & Neon* character (carbon weave, CRT scanlines, mono telemetry,
neon accents used sparingly) and a layer of lab humour that never gets in the way of the data.

## Install

The package is source-distributed (TypeScript + CSS); the consuming Vite app compiles it.

```jsonc
// app/package.json
"dependencies": {
  "@portfolio/aegis-ui": "file:../../packages/aegis-ui",
  "motion": "14.1.1", "cytoscape": "3.34.4", "react": "19.3.1", "react-dom": "19.3.1"
}
```

```css
/* app/src/index.css */
@import "tailwindcss";
@import "@portfolio/aegis-ui/theme.css";   /* tokens, utilities, modes; @source scans the package for classes */
```

```ts
// vite.config.ts: one React for the app and the linked package
resolve: { dedupe: ["react", "react-dom", "motion", "cytoscape", "@radix-ui/react-dialog"] }
```

```jsonc
// tsconfig.json: same idea for the type checker
"baseUrl": ".",
"paths": { "react": ["./node_modules/@types/react"], "react/*": ["./node_modules/@types/react/*"],
           "react-dom": ["./node_modules/@types/react-dom"], "motion/react": ["./node_modules/motion/react"] }
```

Fonts: load Geist and JetBrains Mono (Google Fonts) in `index.html`.

## Tokens

| Tailwind colour | CSS var | Meaning |
|---|---|---|
| `bg`, `panel`, `panel-2`, `line`, `ink`, `muted` | `--ae-*` | obsidian base, glass, 1px frames, text |
| `cyan` (`accent`) | `--ae-cyan` | active, scanning, focus |
| `crimson` (`bad`), `crit` | `--ae-crimson` | breach, isolate, destructive |
| `amber` (`warn`) | `--ae-amber` | drift, warning |
| `green` (`good`) | `--ae-green` | terminal, OK |
| `status-prevented`, `status-detected`, `status-missed`, `status-error`, `status-drift`, `status-remediated`, `status-telemetry`, `status-skipped` | `--ae-status-*` | shared result states (`STATUS` map in TS) |

Utilities: `ae-glass`, `ae-ticks` (bright corner ticks), `ae-scanlines`, `ae-neon-text`, `ae-empty-radial`,
`ae-caret`, `ae-live`, `ae-in`. `data-theme="light"` gives a daylight variant.

## Components

| Export | What it does |
|---|---|
| `TerminalPalette` + `useTerminalHotkey` | zsh-style Ctrl/Cmd+K (or `/`) terminal: async commands, Tab completion, history, inline hold-to-confirm steps, fuzzy "cd" suggestions, and built-ins (`help`, `clear`, `whoami`, `sudo`, `rm -rf /`, `hack`) |
| `HoldToConfirm` | destructive actions fire only after a `duration` ms hold (mouse, touch or Space/Enter); `disabled` + `disabledReason` tooltip |
| `SlideToExecute` | "slide to isolate": drag the knob to the end; a red gradient blooms as it travels; `disabled`/`disabledReason`, keyboard → ×4 |
| `DataWaterfall` | muted, blurred canvas of falling telemetry lines behind a page (decorative, aria-hidden, off with reduced motion) |
| `TextScramble` | cryptographic left-to-right reveal for logs and AI text |
| `GlitchText` | hex-cycling hover/focus effect for critical button labels |
| `CountUp` | animated number counters (MTTR, coverage) with a `format` function |
| `AsciiLoader`, `HexCascade` | ASCII spinner with sarcastic status lines; falling hexdump for long waits |
| `StressGauge` | the Analyst Stress Index and caffeine requirement (`analystStress()` is a tested pure function) |
| `GhostAnnotation` | AI output as inline ghost text with a dashed rail and a "why?" evidence sheet. No chat UI. |
| `Topology` | Cytoscape graph: drag nodes, zoom, click for a glass context card (`renderContext`) |
| `Panel`, `Button`, `Kbd`, `StatusBadge`, `SnarkyEmpty`, `SnarkyError` | shadcn-style primitives (`cva`, `cn`) |
| `ModeProvider`, `useModes`, `useKonami` | ↑↑↓↓←→←→BA turns the UI into a green-phosphor 1993 terminal for 10 s; "deface" simulates a compromised console |
| `SettingsSheet` | theme, phosphor test and, at the bottom under a boring heading, the deface toggle |

Everything honours `prefers-reduced-motion`: scrambles, glitches, counters and flicker are skipped.

## Hidden features (so nobody has to discover them in a demo)

* **Konami code** anywhere outside a text field: green phosphor, scanlines and CRT vignette for 10 seconds.
* **Deface mode** (Settings → "Advanced compliance telemetry (do not touch)"): skull, glitching red headings,
  and an explicit "simulation only, nothing was changed" line. Esc or a click restores.
* **Terminal jokes**: `sudo` reports you to yourself, `rm -rf /` is refused, `hack` hacks the planet, unknown
  commands hint at the Konami code.
* **Empty states** pick a stable quip per screen ("0 alerts found. Either the firewall is working, or it's
  unplugged.").

All of it is cosmetic. None of it can trigger an action, change data or bypass an approval.

## Tests

```bash
npm install && npm test && npm run typecheck   # pure logic: scramble, Konami, stress index, parser, completion
```
