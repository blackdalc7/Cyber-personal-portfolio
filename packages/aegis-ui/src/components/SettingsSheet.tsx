import * as Dialog from "@radix-ui/react-dialog";
import * as Switch from "@radix-ui/react-switch";
import { motion } from "motion/react";
import { useState, type ReactNode } from "react";
import { Cog } from "./icons";
import { useModes } from "./Modes";

function Toggle({ id, checked, onChange, label, hint }: { id: string; checked: boolean; onChange: (v: boolean) => void; label: string; hint?: string }) {
  return (
    <div className="flex items-center justify-between gap-4 py-2">
      <label htmlFor={id} className="text-sm">{label}{hint && <span className="block text-[11px] text-muted">{hint}</span>}</label>
      <Switch.Root id={id} checked={checked} onCheckedChange={onChange}
        className="relative h-5 w-9 shrink-0 border border-line bg-black/40 data-[state=checked]:border-cyan data-[state=checked]:bg-cyan/20">
        <Switch.Thumb className="block h-3.5 w-3.5 translate-x-0.5 bg-muted transition data-[state=checked]:translate-x-[18px] data-[state=checked]:bg-cyan" />
      </Switch.Root>
    </div>
  );
}

/** Settings sheet. The deface toggle sits at the very bottom under a deliberately boring heading. */
export function SettingsSheet({ theme, onTheme, children, version }: {
  theme: "dark" | "light"; onTheme: (t: "dark" | "light") => void; children?: ReactNode; version?: string;
}) {
  const { deface, setDeface, phosphor } = useModes();
  const [open, setOpen] = useState(false);
  return (
    <Dialog.Root open={open} onOpenChange={setOpen}>
      <Dialog.Trigger aria-label="Settings" title="Settings" className="p-2 text-muted hover:text-cyan"><Cog className="h-4 w-4" /></Dialog.Trigger>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm" />
        <Dialog.Content asChild aria-describedby={undefined}>
          <motion.div initial={{ x: 40, opacity: 0 }} animate={{ x: 0, opacity: 1 }}
            className="ae-glass fixed inset-y-0 right-0 z-50 flex w-[min(92vw,380px)] flex-col p-5">
            <Dialog.Title className="font-mono text-xs uppercase tracking-[0.2em] text-cyan">~/.config/settings</Dialog.Title>
            <div className="mt-4 divide-y divide-line">
              <Toggle id="ae-theme" checked={theme === "light"} onChange={(v) => onTheme(v ? "light" : "dark")} label="Daylight mode" hint="for screenshots and people with windows" />
              <div className="flex items-center justify-between py-2 text-sm">
                <span>Phosphor test<span className="block text-[11px] text-muted">10 seconds of 1993. there is also a key sequence.</span></span>
                <button type="button" onClick={() => { phosphor(); setOpen(false); }} className="border border-line px-2 py-1 font-mono text-[11px] text-green hover:border-green">run</button>
              </div>
              {children}
            </div>
            <div className="mt-auto pt-10">
              <div className="font-mono text-[10px] uppercase tracking-[0.2em] text-muted">Advanced compliance telemetry (do not touch)</div>
              <Toggle id="ae-deface" checked={deface} onChange={(v) => { setDeface(v); if (v) setOpen(false); }} label="Simulate console compromise" hint="tabletop drill: what if the SOC itself got owned? Esc restores." />
              {version && <div className="mt-4 font-mono text-[10px] text-muted">{version}</div>}
            </div>
            <Dialog.Close className="absolute right-3 top-3 font-mono text-xs text-muted hover:text-ink">esc</Dialog.Close>
          </motion.div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
