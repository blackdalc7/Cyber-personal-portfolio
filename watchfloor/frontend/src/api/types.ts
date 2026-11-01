// Response shapes of the Watchfloor hub API (and of the static replay files, which mirror it).

export interface Row {
  time: number;
  class_uid: number;
  activity_id: number;
  severity_id: number;
  status_id: number | null;
  uid: string;
  correlation_uid: string | null;
  product: string | null;
  hostname: string | null;
  src_ip: string | null;
  user_name: string | null;
  process_name: string | null;
  process_pid: number | null;
  parent_pid?: number | null;
  cmd_line: string | null;
  file_path: string | null;
  finding_uid: string | null;
  finding_title: string | null;
  techniques: string[];
  scenario: string | null;
  message: string | null;
  desc?: string | null;
  unmapped?: Record<string, unknown>;
}

export interface Summary {
  events_by_class: Record<string, number>;
  findings_by_product: { product: string; n: number }[];
  findings_by_severity: Record<string, number>;
  top_techniques: { technique: string; n: number }[];
  histogram: { bucket: number; events: number; findings: number }[];
  funnel: { stage: string; count: number }[];
  kpis: {
    open_incidents: number;
    incidents: number;
    mtta_s: number | null;
    mttr_s: number | null;
    findings: number;
    events: number;
  };
}

export interface Incident {
  id: string;
  title: string;
  status: string;
  status_id: number;
  severity_id: number;
  host: string | null;
  indicator_ip: string | null;
  decided_by: string | null;
  description: string | null;
  risk_score: number | null;
  time: number;
  timing: Record<string, number>;
  tta_s: number | null;
  ttr_s: number | null;
  scenario: string | null;
}

export interface TreeNode {
  id: string;
  pid: number;
  name: string;
  cmd_line: string | null;
  time: number;
  alerts: string[];
}

export interface ProcessTree {
  host: string;
  nodes: TreeNode[];
  edges: { source: string; target: string }[];
}

export interface TimelineItem {
  time: number;
  kind: "finding" | "activity" | "response";
  title: string | null;
  product: string | null;
  severity_id?: number;
  class_uid?: number;
  actor?: string | null;
  uid?: string;
}

export interface Chain {
  verdict?: string;
  attack_stage?: string;
  summary?: string;
  recommended_actions?: string[];
  alert_count?: number;
  rule_ids?: string[];
}

export interface EvidencePackage {
  incident_id: string;
  host: string;
  created: string;
  sources: string[];
  files: { name: string; sha256: string; bytes: number }[];
  timeline_rows?: number;
  highlights?: { time: string; source: string; title: string; level?: string }[];
  simulated?: boolean;
}

export interface Analysis {
  incident_id: string;
  provider: string;
  model: string;
  verdict: string;
  confidence: number;
  summary: string;
  evidence: { tool_call: string; quote: string }[];
  recommended_actions: string[];
  tool_calls: { id: string; tool: string; arguments: Record<string, unknown>; result_preview: string }[];
  citations_valid?: boolean;
  created?: string;
}

export interface IncidentDetail {
  incident: Incident;
  history: Incident[];
  findings: Row[];
  auth_summary: { status_id: number; src_ip: string | null; user_name: string | null; n: number; first: number; last: number }[];
  chain: Chain | null;
  process_tree: ProcessTree | null;
  timeline: TimelineItem[];
  evidence: EvidencePackage[];
  analyses: Analysis[];
}

export interface Stage {
  id: string;
  name: string;
  tactic: string;
  techniques: string[];
  start: number;
  host: string | null;
  description: string;
}

export interface ScenarioInfo {
  id: string;
  title: string;
  summary: string;
  provenance: string;
  hosts: string[];
  simulated_parts: string[];
  stages: Stage[];
}

export interface ScenarioData extends ScenarioInfo {
  events: Row[];
}

export type Outcome = "detected" | "telemetry_only" | "missed";
/** 07 also scores live endpoints: blocked by protection, failed to run, or not run (dry run). */
export type CoverageOutcome = Outcome | "prevented" | "error" | "skipped";

export interface StageScore {
  stage: string;
  name: string;
  tactic: string;
  techniques: string[];
  start: number;
  outcome: Outcome;
  ttd_ms: number | null;
  findings: { uid: string; title: string; product: string; time: number }[];
  telemetry_events: number;
}

export interface CoverageRunInfo {
  id: string;
  kind: "exercise" | "emulation";
  title: string;
  started: number | null;
  detection_coverage: number;
  telemetry_coverage: number | null;
}

export interface CoverageCell {
  technique: string;
  name?: string;
  tactic?: string;
  outcome: CoverageOutcome;
  ttd_ms?: number | null;
  source_outcome?: string;
  target?: string;
  test?: string;
  findings?: { title: string; product: string }[];
  steps?: unknown[];
}

export interface CoverageMatrix {
  id: string;
  title: string;
  kind: string;
  summary: { detection_coverage: number; telemetry_coverage?: number | null; [k: string]: unknown };
  cells: CoverageCell[];
}

export interface ExposureFinding {
  host: string;
  port: number;
  asset: string;
  banner: string;
  cve: string;
  cvss: number;
  epss: number;
  kev: boolean;
  priority: number;
  blast_radius_score: number;
  chokepoint: number;
  exposure: string;
  criticality: number;
}

export interface AttackPath {
  target: string;
  probability: number;
  path: string[];
  steps: { from: string; to: string; port: number; cve: string }[];
}

export interface Exposure {
  generated: string;
  entry_points: string[];
  attack_paths: AttackPath[];
  findings: ExposureFinding[];
  graph: {
    nodes: { id: string; label: string; kind: string; criticality?: number; exposure?: string; cves?: { cve: string }[] }[];
    edges: { id: string; source: string; target: string; port: number; cve: string }[];
  };
}

export interface RuleInfo {
  id: string;
  title: string;
  status: string;
  level: string;
  techniques: string[];
  logsource: string;
  tests: { name: string; expected: number; got: number; passed: boolean }[];
  path: string;
  queries?: Record<string, string>;
  tuned_from?: string | null;
  description?: string;
}

export interface RulesIndex {
  generated: string | null;
  rules: RuleInfo[];
}

export interface TriageData {
  run: Record<string, unknown>;
  metrics: {
    raw_alerts: number;
    meta_alerts: number;
    analyst_queue: number;
    suppressed_alerts: number;
    queue_reduction_pct: number;
    analyst_hours_before: number;
    analyst_hours_after: number;
    suppression_reasons: Record<string, number>;
  };
  evaluation: { true_threat_recall: number; suppression_precision: number; labelled_alerts: number; noise_removed_pct: number };
  queue: { id: string; count: number; rules: string[]; severity: string; disposition: string; reason: string; signature: string }[];
}

export interface Manifest {
  generated: string;
  ocsf_version: string;
  scenarios: string[];
  incidents: string[];
  has_exposure: boolean;
  has_triage: boolean;
}
