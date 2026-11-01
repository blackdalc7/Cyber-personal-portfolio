import { createContext, useContext, useEffect, useState, type DependencyList, type ReactNode } from "react";
import type { DataSource } from "../api/source";

const Ctx = createContext<DataSource | null>(null);

export function DataProvider({ source, children }: { source: DataSource; children: ReactNode }) {
  return <Ctx.Provider value={source}>{children}</Ctx.Provider>;
}

export function useSource(): DataSource {
  const s = useContext(Ctx);
  if (!s) throw new Error("DataProvider missing");
  return s;
}

/** Load async data with loading/error state; re-runs when `deps` change. */
export function useLoad<T>(fn: (src: DataSource) => Promise<T>, deps: DependencyList = []) {
  const src = useSource();
  const [state, setState] = useState<{ data?: T; error?: unknown; loading: boolean }>({ loading: true });
  useEffect(() => {
    let alive = true;
    setState((s) => ({ ...s, loading: true }));
    fn(src)
      .then((data) => alive && setState({ data, loading: false }))
      .catch((error) => alive && setState({ error, loading: false }));
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [src, ...deps]);
  return state;
}
