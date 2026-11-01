# @portfolio/aegis-ui

The design system behind the Watchfloor console: **Aegis Editorial**. Warm paper and graphite ink with a single
cobalt accent, Newsreader headings over IBM Plex Sans and Plex Mono, sections divided by rules instead of boxed
cards, square corners, and hover states that swap colour instantly. The binding rules (palette, type, layout,
interaction and copy) are in [DESIGN.md](DESIGN.md).

Driftwatch keeps its own copy of the earlier version of this package under `driftwatch/packages/aegis-ui`, so
changes here only affect Watchfloor.

## Install

The package is source-distributed (TypeScript and CSS); the consuming Vite app compiles it.

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
@import "@portfolio/aegis-ui/theme.css";   /* tokens, base type, utilities and hidden modes; @source scans the package */
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

Fonts: load Newsreader (500, 600), IBM Plex Sans (400, 500, 600) and IBM Plex Mono (400, 500) from Google Fonts
in `index.html`.

## Tokens

Components use these semantic Tailwind names only. Each maps to a CSS variable in `src/theme.css`, so the paper
theme, the darkroom theme (`data-theme="dark"`) and the hidden modes restyle everything from one file.

| Tailwind colour | CSS variable | Meaning |
|---|---|---|
| `bg` | `--ae-paper` | page background (raw canvas) |
| `panel-solid` | `--ae-surface` | dialogs and popovers |
| `panel-2` | `--ae-sunken` | code blocks, selected and hovered rows |
| `ink`, `muted` | `--ae-ink`, `--ae-muted` | graphite text, secondary text |
| `line`, `rule` | `--ae-line`, `--ae-rule` | hairlines between rows, strong rules above sections |
| `accent` | `--ae-accent` | links, focus, current selection (cobalt) |
| `good`, `warn`, `bad`, `crit` | `--ae-good` ... | result colours only, always with a text label |
| `status-*` | `--ae-status-*` | shared result states (the `STATUS` map in TypeScript), derived from the above |

Utilities: `ae-section` (rule on top, no box), `ae-surface` (solid ruled dialog surface), `ae-label` (small mono
metadata), plus `ae-live`, `ae-in` and `ae-caret` for the few state-change animations.

## Components

| Export | What it does |
|---|---|
| `Panel` | a page section: strong top rule, serif heading, optional subtitle and actions |
| `Button`, `buttonVariants` | ruled buttons; hover inverts to ink on paper. No transitions, scaling or glow |
| `Kbd`, `StatusBadge` | keyboard key; a result state as glyph plus label in its colour |
| `EmptyState`, `ErrorNotice` | one factual sentence for an empty view; what failed plus guidance for an error |
| `TerminalPalette` + `useTerminalHotkey` | Ctrl/Cmd+K (or `/`) command line: async commands, Tab completion, history, inline hold-to-confirm steps and "jump to" suggestions. Built-ins: `help`, `clear`, `whoami`, `exit` |
| `HoldToConfirm` | destructive actions fire only after a `duration` ms hold (mouse, touch or Space/Enter); `disabled` + `disabledReason` |
| `SlideToExecute` | "slide to isolate": drag the knob to the end; a solid fill tracks progress; keyboard → ×4 |
| `AsciiLoader`, `HexCascade` | a quiet "Loading" line with a blinking underscore, announced to screen readers |
| `GhostAnnotation` | AI output as a marginal note with source, confidence, citation check and a "Show evidence" sheet. No chat UI |
| `Topology` | Cytoscape graph: drag nodes, zoom, click for a context card (`renderContext`) |
| `ModeProvider`, `useModes`, `useKonami` | opt-in cosmetic modes: a ten-second green-screen preview (Konami code) and a "simulate console compromise" tabletop drill |
| `SettingsSheet` | theme switch, the phosphor preview and the tabletop drill |

Everything honours `prefers-reduced-motion`.

## Tests

```bash
npm install && npm test && npm run typecheck   # pure logic: Konami, workload index, parser, completion, hexdump
```
