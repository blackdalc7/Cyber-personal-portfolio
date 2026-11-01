// One interface, two implementations: the live hub API and the static replay files.
// Every page talks to `DataSource`, so the GitHub Pages demo exercises the same UI code as a live deployment.

import type {
  Analysis,
  CoverageMatrix,
  CoverageRunInfo,
  EvidencePackage,
  Exposure,
  Incident,
  IncidentDetail,
  Manifest,
  Row,
  RulesIndex,
  ScenarioData,
  ScenarioInfo,
  StageScore,
  Summary,
  TriageData,
} from "./types";

export type Mode = "live" | "replay";

export interface DataSource {
  mode: Mode;
  manifest(): Promise<Manifest | null>;
  summary(scenario?: string): Promise<Summary>;
  findings(): Promise<Row[]>;
  incidents(): Promise<Incident[]>;
  incident(id: string): Promise<IncidentDetail>;
  scenarios(): Promise<ScenarioInfo[]>;
  scenario(id: string): Promise<ScenarioData>;
  score(id: string): Promise<{ stages: StageScore[] }>;
  coverageRuns(): Promise<CoverageRunInfo[]>;
  coverage(id: string): Promise<CoverageMatrix>;
  exposure(): Promise<Exposure | null>;
  rules(): Promise<RulesIndex>;
  triage(): Promise<TriageData | null>;
  evidence(): Promise<EvidencePackage[]>;
  analyses(): Promise<Analysis[]>;
  /** Ask 02 for a human-approved isolation. Never isolates anything by itself; replay mode only simulates. */
  requestIsolation(host: string, reason: string, incidentId?: string): Promise<IsolationResult>;
  /** Live mode: subscribe to the SSE stream. Returns an unsubscribe function. */
  subscribe?(onRow: (row: Row) => void, onState: (open: boolean) => void): () => void;
}

export interface IsolationResult {
  status: "approval_requested" | "simulated";
  host: string;
  soar?: { incident_id?: string; status?: string };
}

export const safeName = (s: string) => s.replace(/[^A-Za-z0-9._-]/g, "_");

async function getJson<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, init);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText} for ${url}`);
  return (await res.json()) as T;
}

async function optional<T>(p: Promise<T>): Promise<T | null> {
  try {
    return await p;
  } catch {
    return null;
  }
}

export class ReplaySource implements DataSource {
  mode: Mode = "replay";
  constructor(private base: string) {}
  private f<T>(path: string) {
    return getJson<T>(`${this.base}demo/${path}`);
  }
  manifest() { return optional(this.f<Manifest>("manifest.json")); }
  summary(scenario?: string) { return this.f<Summary>(scenario ? `summary/${scenario}.json` : "summary.json"); }
  findings() { return this.f<Row[]>("findings.json"); }
  incidents() { return this.f<Incident[]>("incidents.json"); }
  incident(id: string) { return this.f<IncidentDetail>(`incident/${safeName(id)}.json`); }
  scenarios() { return this.f<ScenarioInfo[]>("scenarios.json"); }
  scenario(id: string) { return this.f<ScenarioData>(`scenario/${safeName(id)}.json`); }
  score(id: string) { return this.f<{ stages: StageScore[] }>(`score/${safeName(id)}.json`); }
  coverageRuns() { return this.f<CoverageRunInfo[]>("coverage.json"); }
  coverage(id: string) { return this.f<CoverageMatrix>(`coverage/${safeName(id)}.json`); }
  exposure() { return optional(this.f<Exposure>("exposure.json")); }
  rules() { return this.f<RulesIndex>("rules.json"); }
  triage() { return optional(this.f<TriageData>("triage.json")); }
  evidence() { return this.f<EvidencePackage[]>("evidence.json"); }
  analyses() { return this.f<Analysis[]>("analyst.json"); }
  async requestIsolation(host: string): Promise<IsolationResult> {
    await new Promise((r) => setTimeout(r, 900));
    return { status: "simulated", host };
  }
}

export class LiveSource implements DataSource {
  mode: Mode = "live";
  constructor(private base = "", private token = "") {}
  private headers(): HeadersInit {
    return this.token ? { Authorization: `Bearer ${this.token}` } : {};
  }
  private f<T>(path: string) {
    return getJson<T>(`${this.base}/api/${path}`, { headers: this.headers() });
  }
  async manifest() { return null; }
  summary(scenario?: string) { return this.f<Summary>(scenario ? `summary?scenario=${encodeURIComponent(scenario)}` : "summary"); }
  findings() { return this.f<Row[]>("findings?limit=1000"); }
  incidents() { return this.f<Incident[]>("incidents"); }
  incident(id: string) { return this.f<IncidentDetail>(`incidents/${encodeURIComponent(id)}`); }
  scenarios() { return this.f<ScenarioInfo[]>("scenarios"); }
  async scenario(id: string) {
    const sc = await this.f<ScenarioInfo & { events: unknown[] }>(`scenarios/${encodeURIComponent(id)}`);
    // The live endpoint returns full OCSF documents; the UI only needs the flat rows.
    const rows = await this.f<Row[]>(`events?scenario=${encodeURIComponent(id)}&limit=2000`);
    return { ...sc, events: rows.sort((a, b) => a.time - b.time) } as ScenarioData;
  }
  score(id: string) { return this.f<{ stages: StageScore[] }>(`scenarios/${encodeURIComponent(id)}/score?source=dataset`); }
  coverageRuns() { return this.f<CoverageRunInfo[]>("coverage"); }
  coverage(id: string) { return this.f<CoverageMatrix>(`coverage/${encodeURIComponent(id)}`); }
  exposure() { return optional(this.f<Exposure>("exposure")); }
  rules() { return this.f<RulesIndex>("rules"); }
  async triage() { return null; }
  evidence() { return this.f<EvidencePackage[]>("evidence"); }
  analyses() { return this.f<Analysis[]>("analyst"); }
  async requestIsolation(host: string, reason: string, incidentId?: string): Promise<IsolationResult> {
    return getJson<IsolationResult>(`${this.base}/api/actions/isolation-request`, {
      method: "POST",
      headers: { ...this.headers(), "Content-Type": "application/json" },
      body: JSON.stringify({ host, reason, incident_id: incidentId }),
    });
  }
  subscribe(onRow: (row: Row) => void, onState: (open: boolean) => void) {
    const qs = this.token ? `?access_token=${encodeURIComponent(this.token)}` : "";
    const es = new EventSource(`${this.base}/api/stream${qs}`);
    es.addEventListener("ocsf", (ev) => onRow(JSON.parse((ev as MessageEvent).data) as Row));
    es.onopen = () => onState(true);
    es.onerror = () => onState(false);
    return () => es.close();
  }
}

declare const __DATA_MODE__: "replay" | "live" | "auto";

/** Pick the data source: forced by the build mode, or live if the hub answers, else the replay files. */
export async function detectSource(): Promise<DataSource> {
  const base = import.meta.env.BASE_URL;
  const token = (() => {
    try {
      return localStorage.getItem("wf.token") ?? "";
    } catch {
      return "";
    }
  })();
  if (__DATA_MODE__ === "replay") return new ReplaySource(base);
  if (__DATA_MODE__ === "live") return new LiveSource("", token);
  try {
    const res = await fetch("api/health", { signal: AbortSignal.timeout(2500) });
    if (res.ok && (res.headers.get("content-type") ?? "").includes("json")) return new LiveSource("", token);
  } catch {
    /* fall through to replay */
  }
  return new ReplaySource(base);
}
