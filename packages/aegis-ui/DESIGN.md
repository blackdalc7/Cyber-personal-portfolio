# Aegis Editorial: design system

The visual rules for Watchfloor (and anything else built on `@portfolio/aegis-ui`). The aim is a console that
reads like a well-set lab notebook or a printed incident report: warm paper, graphite ink, one accent, and type
doing the work that boxes, glows and gradients used to do.

These rules are binding. If a change breaks one, change the rule here first and say why.

## 1. Principles

1. **Evidence first.** Every pixel is there to help someone read an alert, a timeline or a score. Decoration that
   does not carry information is removed.
2. **Print, not product.** Layouts follow a page: a masthead, columns of unequal width, rules between sections,
   generous margins. No dashboards made of identical tiles.
3. **One accent.** Cobalt marks links, focus and the current selection. Status colours exist only to encode a
   result (detected, missed, warning) and are always paired with a text label or glyph.
4. **Plain words.** Labels say what the number is. No jokes in empty states, no buzzwords, no emoji.

## 2. Palette

All colour comes from CSS variables in `src/theme.css`. Components use the semantic Tailwind names in the right
column, never raw hex values.

| Role | Light mode ("paper") | Default ("obsidian") | Tailwind name |
|---|---|---|---|
| Page background, raw canvas | `#f3eee4` | `#09090b` | `bg` |
| Raised surface (dialogs, popovers) | `#faf7f1` | `#18181b` | `panel-solid` |
| Sunken surface (code, hovered rows) | `#ebe4d6` | `#1f1f23` | `panel-2` |
| Graphite text | `#1f1d1a` | `#f4f4f5` | `ink` |
| Secondary text, metadata | `#5c574f` | `#a1a1aa` | `muted` |
| Hairline rule | `#d6cdbc` | `#27272a` | `line` |
| Strong rule (section tops) | `#1f1d1a` | `#3f3f46` | `rule` |
| Accent: cobalt | `#2f4f8f` | `#22e4ff` | `accent` |
| Result: good (moss) | `#4c6a2f` | `#39ff88` | `good` |
| Result: warning (ochre) | `#8a5a00` | `#ffb224` | `warn` |
| Result: bad (oxblood) | `#9e2f22` | `#ff3b5c` | `bad` |
| Result: critical | `#741c12` | `#ff1f4b` | `crit` |

The default theme is the dark "obsidian" console (zinc-950 with neon used only to encode meaning, set in Geist
and JetBrains Mono). Light mode, switched on in Settings, is the cream paper theme described by the rest of this
document. Every text colour passes WCAG AA (4.5:1) on its own background in both themes.

In light mode: no gradients, glows, `backdrop-filter`, glass panels or texture. The obsidian default keeps its
carbon-weave background and neon accents by request, but still uses no glows, blur or scaling hovers.

## 3. Typography

| Use | Family | Weight | Notes |
|---|---|---|---|
| Headings, masthead, key figures | Newsreader (serif) | 500 and 600 | Optical sizes on; tight leading (1.1) |
| Body copy, labels, controls | IBM Plex Sans | 400 and 500 | 15px base, 1.55 leading |
| Data, timestamps, IDs, code, metadata | IBM Plex Mono | 400 and 500 | Tabular figures |

Rules:

- Headings are set entirely in the serif. No mixing a single italic serif word into a sans headline.
- No ultra-thin weights and no oversized display type. The largest size is the page title at 2.25rem.
- Metadata labels are small mono at 11px with modest tracking (0.06em). They are not shouted in wide-tracked caps.
- Numbers in tables and figures use tabular lining figures so columns align.

## 4. Layout

- **Masthead column.** A fixed left column (14rem) holds the wordmark, a numbered text index of pages, and the
  data provenance. On small screens it becomes a single row of text links.
- **Asymmetric page header.** Title on the left seven of twelve columns, the standfirst (what this page shows and
  where the data came from) on the right five, closed by a strong rule.
- **Sections, not cards.** A section is a strong 1px rule on top, a serif heading, then content on the page
  background. No borders on four sides, no fills, no shadows. Content that needs separation uses hairline rules
  and whitespace.
- **Figures.** Key numbers sit in a row of figures, each with a short rule above, a mono label and a serif value.
- **Corners.** 0px everywhere. A 2px radius is allowed only on native form controls the browser draws.
- **Spacing scale.** 4, 8, 12, 16, 24, 32, 48px. Sections are separated by at least 32px.

## 5. Interaction

- Hover: instant colour swap (muted to ink, or ink to accent) or an underline reveal on links. No scaling, no
  glows, no elastic or spring easing.
- Focus: a 2px solid accent outline with a 2px offset on every focusable element.
- Motion: only to show state changes (a dialog fading in, a progress bar filling). Short linear or ease-out
  tweens under 200ms. Everything respects `prefers-reduced-motion`.
- High-friction actions (isolate a host) keep their hold-to-confirm and slide-to-execute guards, restyled as
  plain ruled controls with a solid fill that tracks progress.

## 6. Copy

- State facts: "No findings in this window", not jokes. Error messages say what failed and what to check.
- Mark simulated or recorded data next to the number it affects.
- No emoji as icons. Line icons from `lucide-react` are allowed when paired with a text label.
- Avoid em-dashes. Use a full stop, a colon or a comma.
- Avoid filler words such as "seamless", "elevate", "leverage", "robust" or "cutting-edge".

## 7. Hidden modes

The Konami "phosphor" mode and the "simulate console compromise" drill are opt-in, cosmetic and reversible. They
are kept because the end-to-end tests cover them and they demonstrate a tabletop exercise, but they never appear
unless the viewer asks for them.
