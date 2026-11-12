import type { HostClass } from './hosts.js';

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type Verdict = 'NOT OBSERVED' | 'CLEAN' | 'PHONING HOME' | 'READING SECRETS' | 'ESCAPE CHAIN';

/** What the hooks could actually see. Absent on receipts written before 0.1.0 coverage tracking. */
export interface Coverage {
  /** distinct pids that reported any event (life/start included), i.e. Node processes under hooks */
  hookedProcesses: number;
  /** was the top-level command's own process hooked (false when it is a native binary or a shell wrapper) */
  rootHooked: boolean;
  note?: string;
}

/**
 * Pointer into the analysed event list. `line` is the 0-based index into the time-sorted event
 * list (the order `readEventLog()` returns, i.e. sorted by ts, pid, seq); `pid`+`seq` identify the
 * raw JSONL line independent of sorting.
 */
export interface EvidencePointer {
  line: number;
  pid: number;
  seq: number;
}

export interface Reason {
  code: string;
  severity: Severity;
  text: string;
  evidence: EvidencePointer[];
}

export interface Finding {
  code: string;
  severity: Severity;
  text: string;
  evidence: EvidencePointer[];
  detail?: Record<string, unknown>;
}

export interface HostSummary {
  host: string;
  /** effective class: with includeLocal, local hosts are reported as "unknown" (see `local`) */
  class: HostClass;
  local?: boolean;
  vendor?: string;
  connections: number;
  bytesUp: number;
  bytesDown: number;
  /** indices into the sorted event list */
  evidence: number[];
}

export interface SensitiveRead {
  kind: 'file' | 'clipboard';
  target: string;
  rule?: string;
  label?: string;
  category?: string;
  severity: Severity;
  bytes?: number;
  pid: number;
  ts: number;
  evidence: EvidencePointer;
}

/** A sensitive-path access that FAILED (ENOENT, EACCES, ...). Evidence of looking, not of reading. */
export interface SensitiveProbe {
  target: string;
  error: string;
  rule?: string;
  label?: string;
  pid: number;
  ts: number;
  evidence: EvidencePointer;
}

export interface ChainSource {
  kind: 'file' | 'clipboard';
  target: string;
  bytes?: number;
  ts: number;
  rule?: string;
  evidence: EvidencePointer;
}

export interface Chain {
  id: string;
  kind: 'file-to-socket' | 'file-to-proc' | 'clipboard-to-socket';
  confidence: 'high' | 'medium';
  explanation: string;
  sources: ChainSource[];
  sink: {
    kind: 'socket' | 'proc';
    host: string;
    hostClass: HostClass;
    target: string;
    bytesWritten?: number;
    firstWriteTs?: number;
    pid: number;
    evidence: EvidencePointer[];
  };
  /** ms between (latest) source read and first write / spawn */
  deltaMs: number;
  evidence: EvidencePointer[];
}

export interface ProcInfo {
  pid: number;
  ppid: number;
  target: string;
  argv?: string[];
  startTs?: number;
  endTs?: number;
  exitCode?: number | null;
}

export interface AnalyzeOptions {
  /** treat class "local" hosts as unclassified (fixtures/tests). Default false. */
  includeLocal?: boolean;
  /** chain window: source read -> first socket write / spawn. Default 5000 ms. */
  windowMs?: number;
  /** chain size rule: bytesWritten >= sizeRatio * bytesRead. Default 0.8. */
  sizeRatio?: number;
  /** TXT lookups within txtWindowMs that trigger the DNS tunnelling smell. Default >10 in 10 s. */
  txtCount?: number;
  txtWindowMs?: number;
  /** long-lived socket: open >= longLivedMs with >= longLivedBytes written. Default 30 s / 1 MiB. */
  longLivedMs?: number;
  longLivedBytes?: number;
}

/** The top-level command the harness spawned; lets analyze() tell whether that process itself was hooked. */
export interface RootInfo {
  pid?: number;
  argv0?: string;
}

export interface Analysis {
  schema: 1;
  verdict: Verdict;
  score: number;
  coverage?: Coverage;
  reasons: Reason[];
  hosts: HostSummary[];
  sensitiveReads: SensitiveRead[];
  /** failed accesses to secret-shaped paths; never counted as reads, never part of chains */
  probes: SensitiveProbe[];
  chains: Chain[];
  heuristics: Finding[];
  procs: ProcInfo[];
  envNames: string[];
  counts: Record<string, number>;
  stats: {
    events: number;
    firstTs: number | null;
    lastTs: number | null;
    durationMs: number;
    pids: number;
    connections: number;
    bytesUp: number;
    bytesDown: number;
  };
  options: Required<AnalyzeOptions>;
}
