import * as Dialog from "@radix-ui/react-dialog";
import * as Switch from "@radix-ui/react-switch";
import { motion } from "motion/react";
import { useState, type ReactNode } from "react";
import { Cog } from "./icons";
import { useModes } from "./Modes";

/** A labelled on/off switch: a ruled track with a square thumb that moves instantly. */
function Toggle({ id, checked, onChange, label, hint }: { id: string; checked: boolean; onChange: (v: boolean) => void; label: string; hint?: string }) {
  return (
    <div className="flex items-center justify-between gap-4 py-3">
      <label htmlFor={id} className="text-sm">{label}{hint && <span className="block text-[12px] text-muted">{hint}</span>}</label>
      <Switch.Root id={id} checked={checked} onCheckedChange={onChange}
        className="relative h-5 w-9 shrink-0 border border-rule data-[state=checked]:bg-ink">
        <Switch.Thumb className="block h-3.5 w-3.5 translate-x-0.5 bg-ink data-[state=checked]:translate-x-[18px] data-[state=checked]:bg-bg" />
      </Switch.Root>
    </div>
  );
}

/** Settings sheet: theme, plus the opt-in cosmetic drills at the bottom under a plain heading. */
export function SettingsSheet({ theme, onTheme, children, version }: {
  theme: "dark" | "light"; onTheme: (t: "dark" | "light") => void; children?: ReactNode; version?: string;
}) {
  const { deface, setDeface, phosphor } = useModes();
  const [open, setOpen] = useState(false);
  return (
    <Dialog.Root open={open} onOpenChange={setOpen}>
      <Dialog.Trigger aria-label="Settings" title="Settings" className="p-2 text-muted hover:text-ink"><Cog className="h-4 w-4" /></Dialog.Trigger>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-ink/40" />
        <Dialog.Content asChild aria-describedby={undefined}>
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.12, ease: "easeOut" }}
            className="fixed inset-y-0 right-0 z-50 flex w-[min(92vw,380px)] flex-col border-l border-rule bg-panel-solid p-6">
            <Dialog.Title className="text-2xl font-semibold">Settings</Dialog.Title>
            <div className="mt-4 divide-y divide-line border-y border-line">
              <Toggle id="ae-theme" checked={theme === "light"} onChange={(v) => onTheme(v ? "light" : "dark")} label="Light mode" hint="Cream paper and graphite ink. Off returns to the dark console." />
              <div className="flex items-center justify-between gap-4 py-3 text-sm">
                <span>Phosphor preview<span className="block text-[12px] text-muted">Ten seconds of a 1990s green-screen terminal. Cosmetic only.</span></span>
                <button type="button" onClick={() => { phosphor(); setOpen(false); }} className="border border-rule px-2 py-1 text-[12px] hover:bg-ink hover:text-bg">Run</button>
              </div>
              {children}
            </div>
            <div className="mt-auto pt-10">
              <h3 className="text-base font-semibold">Tabletop drill</h3>
              <Toggle id="ae-deface" checked={deface} onChange={(v) => { setDeface(v); if (v) setOpen(false); }} label="Simulate console compromise" hint="Shows what a defaced console looks like. Nothing changes. Esc restores." />
              {version && <div className="mt-4 ae-label">{version}</div>}
            </div>
            <Dialog.Close className="absolute right-4 top-5 text-[13px] text-muted hover:text-ink">Close</Dialog.Close>
          </motion.div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
