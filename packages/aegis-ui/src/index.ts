// @portfolio/aegis-ui: the shared design system for the portfolio consoles. Rules live in ../DESIGN.md.
export { cn } from "./lib/cn";
export * from "./lib/logic";
export { useKonami } from "./hooks/useKonami";
export { ModeProvider, useModes } from "./components/Modes";
export { HoldToConfirm, SlideToExecute, type Tone } from "./components/HoldToConfirm";
export { AsciiLoader, HexCascade } from "./components/Loaders";
export { Panel, Button, buttonVariants, Kbd, StatusBadge, EmptyState, ErrorNotice } from "./components/Primitives";
export { GhostAnnotation, type Citation } from "./components/GhostAnnotation";
export {
  TerminalPalette, useTerminalHotkey, ok, err, info, warn,
  type TerminalCommand, type TermLine, type CommandResult, type CommandContext, type ConfirmStep, type LineKind,
} from "./components/TerminalPalette";
export { Topology, type TopoNode, type TopoEdge } from "./components/Topology";
export { SettingsSheet } from "./components/SettingsSheet";
export { Sparkles, TerminalIcon, Cog } from "./components/icons";
