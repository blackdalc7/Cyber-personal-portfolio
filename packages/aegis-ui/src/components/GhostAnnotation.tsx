import * as Dialog from "@radix-ui/react-dialog";
import type { ReactNode } from "react";
import { cn } from "../lib/cn";

export interface Citation {
  ref: string;
  quote: string;
}

/**
 * AI output as a marginal note, never a chat. It sits beside the data it explains with an accent rule on the left,
 * states its source and confidence, and "Show evidence" opens the quoted tool results it relied on.
 * `verified=false` marks the note as untrusted because its citations did not check out.
 */
export function GhostAnnotation({ text, source = "AI analyst", confidence, citations = [], verified, className, children }: {
  text: string; source?: string; confidence?: number; citations?: Citation[]; verified?: boolean; className?: string;
  children?: ReactNode;
}) {
  return (
    <aside className={cn("border-l-2 border-accent pl-4", className)} aria-label={`${source} annotation`}>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 ae-label">
        <span className="text-ink">{source}</span>
        {confidence !== undefined && <span>{Math.round(confidence * 100)}% confidence</span>}
        {verified !== undefined && (
          <span className={verified ? "text-good" : "text-bad"}>{verified ? "citations verified" : "citations failed, treat as untrusted"}</span>
        )}
        {citations.length > 0 && (
          <Dialog.Root>
            <Dialog.Trigger className="ml-auto text-accent underline-offset-2 hover:underline">Show evidence</Dialog.Trigger>
            <Dialog.Portal>
              <Dialog.Overlay className="fixed inset-0 z-50 bg-ink/40" />
              <Dialog.Content className="ae-surface fixed left-1/2 top-[15vh] z-50 w-[min(92vw,640px)] -translate-x-1/2 p-6">
                <Dialog.Title className="text-xl font-semibold">Evidence behind this note</Dialog.Title>
                <Dialog.Description className="mt-1 text-[13px] text-muted">Each claim quotes a read-only tool result.</Dialog.Description>
                <ol className="mt-4 max-h-[50vh] divide-y divide-line overflow-y-auto border-y border-line">
                  {citations.map((c, i) => (
                    <li key={i} className="py-2 font-mono text-[12px]">
                      <span className="text-muted">[{c.ref}]</span> <span className="text-ink">“{c.quote}”</span>
                    </li>
                  ))}
                </ol>
                <Dialog.Close className="mt-4 border border-rule px-3 py-1 text-[13px] hover:bg-ink hover:text-bg">Close</Dialog.Close>
              </Dialog.Content>
            </Dialog.Portal>
          </Dialog.Root>
        )}
      </div>
      <p className="mt-1.5 max-w-3xl font-serif text-[1.0625rem] leading-relaxed text-ink">{text}</p>
      {children}
    </aside>
  );
}
