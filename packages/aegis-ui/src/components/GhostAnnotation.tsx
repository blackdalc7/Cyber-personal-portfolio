import * as Dialog from "@radix-ui/react-dialog";
import { Sparkles } from "./icons";
import type { ReactNode } from "react";
import { cn } from "../lib/cn";
import { TextScramble } from "./TextScramble";

export interface Citation {
  ref: string;
  quote: string;
}

/**
 * AI output as an inline annotation, never a chat. Renders as ghost text with a dashed rail next to the data it
 * explains; "why?" opens a glass sheet with the cited evidence. `verified=false` marks it untrusted.
 */
export function GhostAnnotation({ text, source = "AI analyst", confidence, citations = [], verified, className, children }: {
  text: string; source?: string; confidence?: number; citations?: Citation[]; verified?: boolean; className?: string;
  children?: ReactNode;
}) {
  return (
    <aside className={cn("border-l border-dashed border-cyan/50 pl-3", className)} aria-label={`${source} annotation`}>
      <div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.18em] text-cyan/80">
        <Sparkles className="h-3 w-3" />
        <span>{source}</span>
        {confidence !== undefined && <span className="text-muted">{Math.round(confidence * 100)}% conf.</span>}
        {verified !== undefined && (
          <span className={verified ? "text-green" : "text-crimson"}>{verified ? "citations verified" : "citations failed: untrusted"}</span>
        )}
        {citations.length > 0 && (
          <Dialog.Root>
            <Dialog.Trigger className="ml-auto text-muted underline decoration-dotted underline-offset-2 hover:text-cyan">why?</Dialog.Trigger>
            <Dialog.Portal>
              <Dialog.Overlay className="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm" />
              <Dialog.Content className="ae-glass fixed left-1/2 top-[15vh] z-50 w-[min(92vw,640px)] -translate-x-1/2 p-5">
                <Dialog.Title className="font-mono text-xs uppercase tracking-[0.18em] text-cyan">Evidence behind this annotation</Dialog.Title>
                <Dialog.Description className="mt-1 text-xs text-muted">Every claim quotes a read-only tool result.</Dialog.Description>
                <ul className="mt-4 max-h-[50vh] space-y-2 overflow-y-auto">
                  {citations.map((c, i) => (
                    <li key={i} className="border border-line bg-black/30 p-2 font-mono text-[11px]">
                      <span className="text-cyan">[{c.ref}]</span> <span className="text-ink">“{c.quote}”</span>
                    </li>
                  ))}
                </ul>
                <Dialog.Close className="mt-4 border border-line px-3 py-1 font-mono text-xs text-muted hover:text-ink">close</Dialog.Close>
              </Dialog.Content>
            </Dialog.Portal>
          </Dialog.Root>
        )}
      </div>
      <TextScramble as="p" text={text} className="mt-1 text-sm italic leading-relaxed text-ink/70" />
      {children}
    </aside>
  );
}
