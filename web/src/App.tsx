import { useCallback, useEffect, useMemo, useRef, useState } from "react";

type Summary = {
  coverage_gaps?: string[];
  codex_exit_code?: number;
  interpretation?: string;
  linked_tool_processes?: number;
  first_alert_latency_seconds?: number;
};
type Run = {
  run_id: string;
  goal: string;
  started_at: number;
  updated_at: number;
  status: "live" | "complete" | "incomplete";
  summary: Summary | null;
  event_counts: Record<string, number>;
  finding_count: number;
  assessment_count?: number;
  review_count?: number;
  evaluation_label?: string;
  source?: string;
  demo_case?: string;
  legacy?: boolean;
  finding_title?: string | null;
  ingest_errors: number;
};
type Event = {
  index_id?: number;
  metadata: { uid: string };
  class_uid: number;
  activity_name: string;
  time: number;
  message?: string;
  process?: {
    pid: number;
    name: string;
    parent_process?: { pid: number };
    cmd_line?: string;
  };
  actor?: { process?: { pid: number } };
  file?: { path: string };
  dst_endpoint?: { ip?: string; domain?: string; port?: number };
  unmapped?: {
    traceward?: {
      source?: string;
      event_id?: string;
      pid?: number;
      event_kind?: string;
      process_key?: string;
      parent_process_key?: string;
      raw_trace_ref?: string;
      hook_event?: string;
      apparent_command?: string;
      tool_use_id?: string;
      endpoint?: string;
      byte_count?: number;
      operation_status?: string;
      errno?: number;
      result?: number;
      exit_status?: number;
      details?: Record<string, unknown>;
    };
  };
};
type Finding = {
  finding_id: string;
  revision: number;
  time: number;
  title: string;
  message: string;
  status: string;
  attribution: string;
  tool_use_id?: string;
  evidence_ids: string[];
  observed_effects: string[];
  counterevidence: string[];
  coverage_gaps: string[];
  uncalibrated_risk_score: number | null;
  assessment_note?: string;
  is_alert?: boolean;
  assessment?: Record<string, {status: string; summary: string; evidence_ids: string[]}>;
  verified_claims?: {fact_type: string; evidence_ids: string[]}[];
  laya?: {
    status: string;
    reason?: string;
    model?: string;
    semantic_accuracy_validated?: boolean;
    dimensions?: Record<string, number>;
    disposition?: string;
    rationale?: string;
    cited_evidence_ids?: string[];
  };
  revisions: Finding[];
};
type Raw = { source: string; lines: { line: number; text: string }[] };

const short = (value: string, size = 8) => value?.slice(0, size) || "—";
const date = (value?: number, millis = false) =>
  value ? new Date(value * (millis ? 1 : 1000)).toLocaleString() : "—";
const kind = (event: Event) => {
  if (event.unmapped?.traceward?.event_kind) return event.unmapped.traceward.event_kind;
  if (event.class_uid === 0)
    return event.unmapped?.traceward?.hook_event ? "hook" : "coverage";
  if (event.class_uid === 1001)
    return event.activity_name === "Read"
      ? "file_read"
      : event.activity_name === "Update"
        ? "file_write"
        : "file_open";
  if (event.class_uid === 1007) return "process";
  if (event.class_uid === 4001)
    return event.activity_name === "Traffic" ? "network_send" : "network";
  if (event.class_uid === 2004) return "finding";
  return "other";
};
const eventTitle = (event: Event) => {
  const meta = event.unmapped?.traceward;
  const detail = meta?.details;
  if (kind(event) === 'file_state') return `${String(detail?.change || detail?.phase || 'Observed state')} · ${String(detail?.path || 'repository file')}`;
  if (kind(event) === 'context' || kind(event) === 'agent_claim') return `${String(detail?.role || 'Captured context')} · ${String(detail?.source_reference || detail?.source || '')}`;
  if (kind(event) === 'permission') return `${String(detail?.action || 'Permission evidence')} · ${String(detail?.scope || 'scope unknown')}`;
  if (kind(event) === 'independent_validation') return detail?.passed === true ? 'Independent validation passed' : detail?.passed === false ? 'Independent validation failed' : 'Independent validation unavailable';
  const outcome = meta?.operation_status === "failed" ? "Failed attempt · " : meta?.operation_status === "pending" ? "Pending connection · " : "";
  if (kind(event) === "hook")
    return `${meta?.hook_event || "Hook"} · ${meta?.apparent_command || "tool call"}`;
  if (kind(event) === "process")
    return event.process?.cmd_line || event.process?.name || "Process launched";
  if (kind(event).startsWith("file"))
    return outcome + (event.file?.path || "File operation");
  if (kind(event).startsWith("network"))
    return outcome + (
      meta?.endpoint ||
      `${event.dst_endpoint?.domain || event.dst_endpoint?.ip || "Network"}:${event.dst_endpoint?.port || ""}`
    );
  return event.message || event.activity_name;
};
const eventPid = (event: Event) =>
  event.process?.pid || event.actor?.process?.pid || event.unmapped?.traceward?.pid;
const icon: Record<string, string> = {
  hook: "⌘",
  process: "▣",
  file_open: "◫",
  file_read: "↘",
  file_write: "↗",
  network: "◎",
  network_send: "↗",
  finding: "!",
  coverage: "◌",
};

async function get<T>(path: string): Promise<T> {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok)
    throw new Error(`${response.status} ${response.statusText}`);
  return response.json();
}

export default function App() {
  const [runs, setRuns] = useState<Run[]>([]);
  const [runId, setRunId] = useState<string>("");
  const [events, setEvents] = useState<Event[]>([]);
  const [processes, setProcesses] = useState<Event[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [assessmentAudit, setAssessmentAudit] = useState(false);
  const [evidence, setEvidence] = useState<Event[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<string>("");
  const [selectedEvent, setSelectedEvent] = useState<Event | null>(null);
  const [tab, setTab] = useState<"timeline" | "processes">("timeline");
  const [filter, setFilter] = useState("evidence");
  const [view, setView] = useState<"combined" | "hooks" | "runtime">(
    "combined",
  );
  const [error, setError] = useState("");
  const [raw, setRaw] = useState<Raw | null>(null);
  const [older, setOlder] = useState<number | null>(null);
  const [evaluations, setEvaluations] = useState<{finding_id: string; revision: number; packet: unknown; judgement: unknown}[]>([]);
  const [loadedRun, setLoadedRun] = useState("");
  const activeRun = useRef(runId);
  const paginationStarted = useRef(false);
  activeRun.current = runId;

  const loadRuns = useCallback(async () => {
    try {
      const data = await get<{ runs: Run[] }>("/api/runs");
      setRuns(data.runs);
      setRunId((current) => current || data.runs[0]?.run_id || "");
      setError("");
    } catch (exc) {
      setError(`Cannot read runs: ${String(exc)}`);
    }
  }, []);
  const loadRun = useCallback(async () => {
    if (!runId) return;
    try {
      const [eventData, findingData, processData, evaluationData] = await Promise.all([
        get<{ events: Event[]; next_before: number | null }>(
          `/api/runs/${runId}/events?limit=250`,
        ),
        get<{ findings?: Finding[]; assessments?: Finding[] }>(`/api/runs/${runId}/${assessmentAudit ? 'assessments' : 'findings'}`),
        get<{ processes: Event[] }>(`/api/runs/${runId}/processes`),
        get<{ evaluations: typeof evaluations }>(`/api/runs/${runId}/evaluations`),
      ]);
      if (activeRun.current !== runId) return;
      setEvents(current => {
        const merged = new Map([...current, ...eventData.events].map(e => [e.metadata.uid, e]));
        return [...merged.values()].sort((a, b) => a.time - b.time || (a.index_id || 0) - (b.index_id || 0));
      });
      setProcesses(processData.processes);
      setOlder(current => paginationStarted.current ? current : eventData.next_before);
      const visible = findingData.assessments ?? findingData.findings ?? [];
      setFindings(visible);
      setEvaluations(evaluationData.evaluations);
      setLoadedRun(runId);
      setSelectedFinding((current) =>
        current && visible.some((f) => f.finding_id === current)
          ? current
          : visible[0]?.finding_id || "",
      );
      setError("");
    } catch (exc) {
      setError(`Cannot read run: ${String(exc)}`);
    }
  }, [runId, assessmentAudit]);
  useEffect(() => {
    void loadRuns();
    const stream = new EventSource("/api/stream");
    stream.onmessage = () => {
      void loadRuns();
    };
    // Embedded browsers/proxies may buffer SSE. Polling is an independent fallback.
    const timer = window.setInterval(() => void loadRuns(), 2000);
    return () => { stream.close(); window.clearInterval(timer); };
  }, [loadRuns]);
  useEffect(() => {
    setEvents([]);
    setProcesses([]);
    setFindings([]);
    setSelectedEvent(null);
    setSelectedFinding("");
    setEvidence([]);
    setOlder(null);
    paginationStarted.current = false;
    void loadRun();
  }, [runId, loadRun]);
  useEffect(() => {
    const stream = new EventSource("/api/stream");
    stream.onmessage = () => {
      void loadRun();
    };
    const timer = window.setInterval(() => void loadRun(), 2000);
    return () => { stream.close(); window.clearInterval(timer); };
  }, [loadRun]);
  const run = runs.find((item) => item.run_id === runId);
  const finding = findings.find((item) => item.finding_id === selectedFinding);
  useEffect(() => {
    if (!runId || !finding?.evidence_ids?.length) {
      setEvidence([]);
      return;
    }
    let cancelled = false;
    void get<{ events: Event[] }>(
      `/api/runs/${runId}/evidence?ids=${encodeURIComponent(finding.evidence_ids.join(","))}`,
    )
      .then((data) => { if (!cancelled) setEvidence(data.events); })
      .catch(() => { if (!cancelled) setEvidence([]); });
    return () => { cancelled = true; };
  }, [runId, finding?.finding_id, finding?.revision]);
  const shown = useMemo(
    () =>
      (filter === "evidence" && finding ? evidence : events).filter((event) => {
        const itemKind = kind(event);
        if (view === "hooks" && itemKind !== "hook") return false;
        if (
          view === "runtime" &&
          (itemKind === "hook" ||
            itemKind === "finding" ||
            itemKind === "coverage")
        )
          return false;
        return filter === "all" || filter === "evidence" || itemKind === filter;
      }),
    [events, evidence, finding, filter, view],
  );
  const processDepths = useMemo(() => {
    const parents = new Map<string | number, string | number>();
    for (const event of processes) {
      const pid = event.unmapped?.traceward?.process_key || event.process?.pid;
      const parent = event.unmapped?.traceward?.parent_process_key || event.process?.parent_process?.pid;
      if (pid && parent) parents.set(pid, parent);
    }
    const depth = (pid: string | number) => {
      let current = pid;
      let level = 0;
      const seen = new Set<string | number>();
      while (parents.has(current) && !seen.has(current) && level < 8) {
        seen.add(current);
        current = parents.get(current)!;
        level++;
      }
      return level;
    };
    return new Map(processes.map((event) => [event.metadata.uid, depth(event.unmapped?.traceward?.process_key || event.process?.pid || 0)]));
  }, [processes]);
  const total = Object.values(run?.event_counts || {}).reduce(
    (a, b) => a + b,
    0,
  );
  const rawRef = selectedEvent?.unmapped?.traceward?.raw_trace_ref;
  const rawMatch = rawRef && /^raw\.(strace|gvisor\.jsonl):(\d+)$/.exec(rawRef);
  const rawLine = rawMatch && rawMatch[2];
  const rawSource = rawMatch && (rawMatch[1] === "strace" ? "strace" : "gvisor");

  async function loadOlder() {
    if (!older || !runId) return;
    paginationStarted.current = true;
    const result = await get<{ events: Event[]; next_before: number | null }>(
      `/api/runs/${runId}/events?limit=250&before=${older}`,
    );
    if (activeRun.current !== runId) return;
    setEvents((current) => [...new Map([...result.events, ...current].map(e => [e.metadata.uid, e])).values()]
      .sort((a, b) => a.time - b.time || (a.index_id || 0) - (b.index_id || 0)));
    setOlder(result.next_before);
  }
  async function openRaw(source: string, line: number) {
    if (!runId) return;
    try {
      const result = await get<Raw>(
        `/api/runs/${runId}/raw?source=${source}&line=${line}`,
      );
      setRaw(result);
    } catch (exc) {
      setError(`Cannot open raw excerpt: ${String(exc)}`);
    }
  }

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            T<span>·</span>
          </div>
          <div>
            <strong>TraceWard</strong>
            <small>INVESTIGATION CONSOLE</small>
          </div>
        </div>
        <div className="side-section">
          <span>WORKSPACE</span>
          <button className="active-nav">
            ▦ <b>Agent runs</b>
            <em>{runs.length}</em>
          </button>
        </div>
        <div className="side-heading">
          <span>RECENT RUNS</span>
          <span className="pulse" title="Live updates connected" />
        </div>
        <div className="run-list">
          {runs.map((item) => (
            <button
              key={item.run_id}
              data-run-id={item.run_id}
              className={`run-card ${item.run_id === runId ? "selected" : ""}`}
              onClick={() => setRunId(item.run_id)}
            >
              <div className="run-card-top">
                <span className={`status-dot ${item.status}`} />{" "}
                <span className="run-time">{date(item.started_at)}</span>{" "}
                <span className="mini-count">
                  {item.finding_count
                    ? `${item.finding_count} finding${item.finding_count === 1 ? "" : "s"}`
                    : "No findings"}
                </span>
              </div>
              <strong>{item.goal}</strong>
              {item.finding_title && (
                <span className="run-finding-title" title={item.finding_title}>
                  {item.finding_title}
                </span>
              )}
              <small>
                {short(item.run_id, 14)} · {item.status}
              </small>
              <small>{item.legacy ? "Historical run · " : `${item.source} · `}{item.evaluation_label}</small>
            </button>
          ))}
        </div>
        {!runs.length && (
          <p className="empty-side">
            No runs yet. Start an observed agent or replay a fixture.
          </p>
        )}
        <div className="side-footer">
          <span className="green-dot" /> LOCAL ONLY{" "}
          <small>OCSF 1.8 · Observe-only</small>
        </div>
      </aside>
      <main className="main">
        <header className="topbar">
          <div className="breadcrumb">
            Workspace <span>/</span> Agent runs <span>/</span>{" "}
            <b>{run ? short(run.run_id, 8) : "Overview"}</b>
          </div>
          <div className="top-actions">
            <span className="live-indicator">
              <i /> LIVE SYNC
            </span>
            <span className="avatar">D</span>
          </div>
        </header>
        {error && <div className="error-banner">{error}</div>}
        {!run ? (
          <div className="welcome">
            <div className="welcome-glyph">⌁</div>
            <h1>See what your agent actually did.</h1>
            <p>
              Run TraceWard around Codex to connect tool intent with process,
              file, and network effects. Evidence appears here as it is
              recorded.
            </p>
            <code>
              traceward run --goal "Fix the failing test" codex exec …
            </code>
          </div>
        ) : (
          <>
            <div className="content-header">
              <div>
                <div className="eyebrow">
                  RUN / {short(run.run_id, 12)}{" "}
                  <span className={`status-label ${run.status}`}>
                    {run.status}
                  </span>
                </div>
                <h1>Agent investigation</h1>
                <p>
                  Started {date(run.started_at)} · {total.toLocaleString()}{" "}
                  recorded events
                </p>
              </div>
              <div className="header-meta">
                <span>Run ID</span>
                <code>{run.run_id}</code>
              </div>
            </div>
            <section className="goal-card">
              <div className="goal-icon">◎</div>
              <div>
                <div className="eyebrow">AUTHORISED GOAL</div>
                <p>{run.goal}</p>
                <small>{run.source} {run.demo_case && `· ${run.demo_case}`} · {run.evaluation_label}{run.legacy && " · historical results were not revalidated"}</small>
              </div>
            </section>
            <div className="metrics">
              <div className="metric">
                <span>EVENTS OBSERVED</span>
                <strong>{total.toLocaleString()}</strong>
                <small>Hooks + runtime</small>
              </div>
              <div className="metric">
                <span>PROCESS ACTIVITY</span>
                <strong>{run.event_counts.process || 0}</strong>
                <small>Forks and execs observed</small>
              </div>
              <div className="metric">
                <span>FILE EFFECTS</span>
                <strong>
                  {(run.event_counts.file_read || 0) +
                    (run.event_counts.file_write || 0)}
                </strong>
                <small>Confirmed reads / writes</small>
              </div>
              <div className={`metric ${run.finding_count ? "highlight" : ""}`}>
                <span>FINDINGS</span>
                <strong>{run.finding_count}</strong>
                <small>{run.assessment_count ?? run.finding_count} internal assessments</small>
              </div>
            </div>
            <div className="workspace-grid">
              <section className="trace-panel" data-loaded-events={events.length}>
                <div className="panel-head">
                  <div>
                    <div className="eyebrow">OBSERVABILITY</div>
                    <h2>Evidence stream</h2>
                  </div>
                  <div className="segment">
                    <button
                      className={tab === "timeline" ? "on" : ""}
                      onClick={() => setTab("timeline")}
                    >
                      Timeline
                    </button>
                    <button
                      className={tab === "processes" ? "on" : ""}
                      onClick={() => setTab("processes")}
                    >
                      Processes
                    </button>
                  </div>
                </div>
                <div className="toolbar">
                  <div className="segment subtle">
                    <button
                      className={view === "combined" ? "on" : ""}
                      onClick={() => setView("combined")}
                    >
                      Combined
                    </button>
                    <button
                      className={view === "hooks" ? "on" : ""}
                      onClick={() => setView("hooks")}
                    >
                      Hooks only
                    </button>
                    <button
                      className={view === "runtime" ? "on" : ""}
                      onClick={() => setView("runtime")}
                    >
                      Runtime only
                    </button>
                  </div>
                  <select
                    aria-label="Event type"
                    value={filter === "evidence" && !finding ? "all" : filter}
                    onChange={(event) => setFilter(event.target.value)}
                  >
                    <option value="evidence">Finding evidence</option>
                    <option value="all">All events</option>
                    <option value="hook">Hooks</option>
                    <option value="process">Processes</option>
                    <option value="file_read">File reads</option>
                    <option value="file_write">File writes</option>
                    <option value="network_send">Network sends</option>
                    <option value="finding">Findings</option>
                    <option value="coverage">Coverage</option>
                  </select>
                </div>
                {tab === "timeline" ? (
                  <div className="event-list">
                    {older && filter !== "evidence" && (
                      <button
                        className="load-more"
                        onClick={() => void loadOlder()}
                      >
                        Load earlier events
                      </button>
                    )}
                    {shown.map((event) => (
                      <button
                        key={event.metadata.uid}
                        data-event-id={event.metadata.uid}
                        data-kind={kind(event)}
                        data-time={event.time}
                        className={`event-row ${selectedEvent?.metadata.uid === event.metadata.uid ? "picked" : ""}`}
                        onClick={() => {
                          setSelectedEvent(event);
                        }}
                      >
                        <span className={`event-icon ${kind(event)}`}>
                          {icon[kind(event)] || "·"}
                        </span>
                        <span className="event-body">
                          <span className="event-title">
                            {eventTitle(event)}
                          </span>
                          <span className="event-sub">
                            {kind(event).replace("_", " ")} ·{" "}
                            {event.unmapped?.traceward?.source || "traceward"}{" "}
                            {eventPid(event) ? `· PID ${eventPid(event)}` : ""}
                          </span>
                        </span>
                        <time>{new Date(event.time).toLocaleTimeString(undefined, {hour: "2-digit", minute: "2-digit", second: "2-digit", fractionalSecondDigits: 3})}</time>
                      </button>
                    ))}
                    {!shown.length && (
                      <div className="empty-list">
                        No events match this view.
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="process-list">
                    {(view === "hooks" ? [] : processes).map((event) => (
                      <button
                        key={event.metadata.uid}
                        data-depth={processDepths.get(event.metadata.uid) || 0}
                        onClick={() => {
                          setSelectedEvent(event);
                        }}
                      >
                        <span className="process-line">└─</span>
                        <span>
                          <b>{event.process?.name || "process"}</b>
                          <small>
                            PID {event.process?.pid} · parent{" "}
                            {event.process?.parent_process?.pid ?? "unknown"}
                          </small>
                        </span>
                      </button>
                    ))}
                    {(!processes.length || view === "hooks") && (
                      <div className="empty-list">No process evidence yet.</div>
                    )}
                  </div>
                )}
              </section>
              <aside className="inspector">
                <div className="panel-head">
                  <div>
                    <div className="eyebrow">INVESTIGATION</div>
                    <h2>
                      {selectedEvent
                        ? "Event details"
                        : assessmentAudit ? 'Assessment audit' : 'Findings'}
                    </h2>
                  </div>
                  {!selectedEvent && <button type="button" onClick={() => {
                    setFindings([]); setSelectedFinding(''); setAssessmentAudit(current => !current);
                  }}>{assessmentAudit ? 'Back to findings' : 'Assessment audit'}</button>}
                  {selectedEvent && (
                    <button
                      className="close"
                      onClick={() => setSelectedEvent(null)}
                    >
                      ×
                    </button>
                  )}
                </div>
                {selectedEvent ? (
                  <div className="inspector-scroll">
                    <span className={`pill ${kind(selectedEvent)}`}>
                      {kind(selectedEvent).replace("_", " ")}
                    </span>
                    <h3>{eventTitle(selectedEvent)}</h3>
                    <div className="detail-pair">
                      <span>Evidence ID</span>
                      <code>{selectedEvent.metadata.uid}</code>
                    </div>
                    <div className="detail-pair">
                      <span>Observed at</span>
                      <b>{date(selectedEvent.time, true)}</b>
                    </div>
                    <div className="detail-pair">
                      <span>Source</span>
                      <b>
                        {selectedEvent.unmapped?.traceward?.source ||
                          "traceward"}
                      </b>
                    </div>
                    <div className="detail-pair">
                      <span>PID</span>
                      <b>
                        {eventPid(selectedEvent) || "—"}
                      </b>
                    </div>
                    {selectedEvent.unmapped?.traceward?.tool_use_id && (
                      <div className="detail-pair">
                        <span>Tool call</span>
                        <code>
                          {selectedEvent.unmapped.traceward.tool_use_id}
                        </code>
                      </div>
                    )}
                    {selectedEvent.unmapped?.traceward?.operation_status && <div className="detail-pair"><span>Operation outcome</span><b>{selectedEvent.unmapped.traceward.operation_status}{selectedEvent.unmapped.traceward.errno ? ` · errno ${selectedEvent.unmapped.traceward.errno}` : ""}</b></div>}
                    {selectedEvent.unmapped?.traceward?.byte_count !== undefined && <div className="detail-pair"><span>Observed bytes</span><b>{selectedEvent.unmapped.traceward.byte_count}</b></div>}
                    {selectedEvent.unmapped?.traceward?.process_key && <div className="detail-pair"><span>Process identity</span><code>{selectedEvent.unmapped.traceward.process_key}</code></div>}
                    {selectedEvent.unmapped?.traceward?.details && <div className="semantic-evidence">
                      <div className="section-label">SOURCE EVIDENCE</div>
                      <pre className="evaluation-json">{JSON.stringify(selectedEvent.unmapped.traceward.details, null, 2)}</pre>
                    </div>}
                    {rawLine && (
                      <button
                        className="raw-button"
                        onClick={() => void openRaw(rawSource || "gvisor", Number(rawLine))}
                      >
                        View raw trace excerpt ↗
                      </button>
                    )}
                    {kind(selectedEvent) === "hook" && (
                      <button
                        className="raw-button"
                        onClick={() => void openRaw("hooks", 1)}
                      >
                        View raw hook log ↗
                      </button>
                    )}
                    <p className="footnote">
                      Raw records may contain sensitive command arguments. They
                      are never loaded automatically.
                    </p>
                  </div>
                ) : (
                  <div className="inspector-scroll">
                    {findings.length ? (
                      <>
                        <div className="finding-tabs">
                          {findings.map((item) => (
                            <button
                              key={item.finding_id}
                              className={
                                selectedFinding === item.finding_id ? "on" : ""
                              }
                              onClick={() =>
                                setSelectedFinding(item.finding_id)
                              }
                            >
                              {short(item.finding_id)} · r{item.revision}
                            </button>
                          ))}
                        </div>
                        {finding && (
                          <>
                            <div className="finding-alert" data-status={finding.status} data-revision={finding.revision}>
                              <span className="finding-badge">
                                {(finding.status === 'provisional' && finding.is_alert === false ? 'Investigation candidate' : finding.status === "suspicious_behaviour" ? "legacy provisional alert" : finding.status).replaceAll("_", " ").toUpperCase()}
                              </span>
                              <h3>{finding.title}</h3>
                              <p>{finding.message}</p>
                              <small>
                                {finding.attribution} ·{" "}
                                {finding.observed_effects.join(" + ")}
                              </small>
                            </div>
                            {finding.assessment_note && <p>{finding.assessment_note}</p>}
                            <div className="section-label">
                              DECISION MODEL · {finding.laya?.status === "unavailable"
                                ? "UNAVAILABLE"
                                : finding.laya?.model || "PENDING"}
                            </div>
                            {finding.laya?.status === "assessed" ? (
                              <div className="score-card structured-assessment">
                                <div className="score-top">
                                  <div><span>MODEL VERDICT</span><strong>{finding.laya.disposition?.replaceAll("_", " ")}</strong></div>
                                  <span className="score-tag">{finding.laya.model?.includes("demo") ? "SIMULATED EVALUATOR" : "STRUCTURED MODEL REVIEW"}</span>
                                </div>
                                <p className="judge-rationale">{finding.laya.rationale}</p>
                                {finding.assessment && <div className="assessment-facets">
                                  {Object.entries(finding.assessment).map(([name, facet]) => <section key={name} className="assessment-facet" data-status={facet.status}>
                                    <div><strong>{name.replaceAll('_', ' ')}</strong><span>{facet.status.replaceAll('_', ' ')}</span></div>
                                    <p>{facet.summary}</p>
                                    <div className="judge-citations">{facet.evidence_ids.map(id => {
                                      const item = evidence.find(e => e.metadata.uid === id);
                                      return <button key={id} disabled={!item} onClick={() => item && setSelectedEvent(item)} aria-label={`${name} evidence ${id}`}>{short(id, 12)}</button>;
                                    })}</div>
                                  </section>)}
                                </div>}
                                {finding.verified_claims?.length ? <div className="supported-facts"><strong>Evidence predicates checked</strong>
                                  <ul>{finding.verified_claims.map((claim, i) => <li key={i}>{claim.fact_type.replaceAll('_', ' ')} · {claim.evidence_ids.map(id => short(id)).join(', ')}</li>)}</ul>
                                  <p>These checks validate typed evidence predicates; model interpretations can still be wrong.</p>
                                </div> : null}
                                <div className="judge-citations">{finding.laya.cited_evidence_ids?.map(id => {
                                  const item = evidence.find(e => e.metadata.uid === id);
                                  return <button key={id} disabled={!item} onClick={() => item && setSelectedEvent(item)} aria-label={`Judge evidence ${id}`}>{short(id, 16)}</button>;
                                })}</div>
                                <p>No numerical risk score. This verdict is not a confirmed violation or proof of safety.</p>
                                <p>Experimental judgement: validation covers reviewed cases; production accuracy is not established.</p>
                              </div>
                            ) : finding.laya?.status === "scored" ? (
                              <div className="score-card">
                                <div className="score-top">
                                  <div>
                                    <span>UNCALIBRATED RISK SCORE</span>
                                    <strong>
                                      {Math.round(
                                        (finding.uncalibrated_risk_score || 0) *
                                          100,
                                      )}
                                      <small>/100</small>
                                    </strong>
                                  </div>
                                  <span className="score-tag">
                                    {finding.laya?.model?.includes("demo") ? "SIMULATED EVALUATOR" : "MODEL REVIEW"}
                                  </span>
                                </div>
                                <div className="score-bars">
                                  {Object.entries(
                                    finding.laya.dimensions || {},
                                  ).map(([key, value]) => (
                                    <div key={key}>
                                      <div>
                                        <span>{key.replaceAll("_", " ")}</span>
                                        <b>{Math.round(value * 100)}%</b>
                                      </div>
                                      <progress className="score-progress" value={value} max={1} />
                                    </div>
                                  ))}
                                </div>
                                <p>
                                  This score is not a probability of
                                  misalignment or a confirmed violation.
                                </p>
                                {finding.laya.semantic_accuracy_validated === false && (
                                  <p>Experimental judgement: semantic accuracy is not validated. The current Laya checkpoint has a known authorised-control false positive.</p>
                                )}
                                {run.legacy && <p>Historical assessment: limited context and simulated scores have not been revalidated.</p>}
                              </div>
                            ) : (
                              <div className="model-unavailable">
                                {finding.laya
                                  ? `Judgement unavailable (${finding.laya.reason || "no score"}).`
                                  : "Provisional finding. Waiting for the decision model…"}{" "}
                                The observed evidence remains available.
                              </div>
                            )}
                            <div className="section-label">
                              CAUSAL EVIDENCE · {finding.evidence_ids.length}{" "}
                              IDS
                            </div>
                            <div className="section-label">COUNTEREVIDENCE & LIMITS</div>
                            <ul className="gaps">{finding.counterevidence.map((item, index) => <li key={index}>{item}</li>)}</ul>
                            <details>
                              <summary>Inspect exact evaluation packet and typed response</summary>
                              <pre className="evaluation-json">{evaluations.some(item => item.finding_id === finding.finding_id) ? JSON.stringify(evaluations.filter(item => item.finding_id === finding.finding_id), null, 2) : "No audit packet recorded for this historical assessment."}</pre>
                            </details>
                            <div className="evidence-chain">
                              {finding.evidence_ids.map((id, index) => {
                                const item = evidence.find(
                                  (event) => event.metadata.uid === id,
                                );
                                return (
                                  <button
                                    key={id}
                                    onClick={() =>
                                      item && setSelectedEvent(item)
                                    }
                                  >
                                    <span className="chain-index">
                                      {String(index + 1).padStart(2, "0")}
                                    </span>
                                    <span>
                                      <b>
                                        {item
                                          ? eventTitle(item)
                                          : "Evidence not indexed yet"}
                                      </b>
                                      <small>
                                        {item
                                          ? kind(item).replace("_", " ")
                                          : ""}{" "}
                                        · {short(id, 16)}
                                      </small>
                                    </span>
                                    <span>↗</span>
                                  </button>
                                );
                              })}
                            </div>
                            <div className="section-label">
                              REVISION HISTORY
                            </div>
                            <div className="revision-list">
                              {finding.revisions.map((item) => (
                                <div key={item.revision}>
                                  <b>r{item.revision}</b>
                                  <span>
                                    {item.laya?.status === "assessed" ? "Structured model assessment" : item.laya?.status === "scored"
                                      ? item.laya.model?.includes("demo")
                                        ? "Simulated evaluator"
                                        : "Model evaluation"
                                      : item.laya
                                        ? "Model unavailable"
                                        : "Provisional evidence finding"}
                                  </span>
                                  <time>{date(item.time)}</time>
                                </div>
                              ))}
                            </div>
                            {[...new Set([...(finding.coverage_gaps || []), ...(run.summary?.coverage_gaps || [])])].length > 0 && (
                              <>
                                <div className="section-label">
                                  COVERAGE GAPS
                                </div>
                                <ul className="gaps">
                                  {[...new Set([...(finding.coverage_gaps || []), ...(run.summary?.coverage_gaps || [])])].map((gap) => (
                                    <li key={gap}>{gap}</li>
                                  ))}
                                </ul>
                              </>
                            )}
                          </>
                        )}
                      </>
                    ) : (
                      <div className="no-findings">
                        <div>—</div>
                        <h3>{loadedRun === runId ? assessmentAudit ? 'No assessments' : "No review findings" : "Loading assessment…"}</h3>
                        <p>
                          {loadedRun === runId ? "Cleared and incomplete assessments are available in Assessment audit. No finding is not proof of safety." : "Loading evidence. No conclusion is available yet."}
                        </p>
                      </div>
                    )}
                    {run.summary?.coverage_gaps?.length && !findings.length ? (
                      <ul className="gaps">
                        {run.summary.coverage_gaps.map((gap) => (
                          <li key={gap}>{gap}</li>
                        ))}
                      </ul>
                    ) : null}
                  </div>
                )}
              </aside>
            </div>
            <div className="footer-note">
              TRACEWARD IS OBSERVE-ONLY · Findings require human review · Event
              loss and attribution limits are reported, not hidden.
            </div>
          </>
        )}
      </main>
      {raw && (
        <div className="modal-backdrop">
          <div className="modal raw-modal">
            <button className="close" onClick={() => setRaw(null)}>
              ×
            </button>
            <h2>Raw {raw.source} excerpt</h2>
            <pre>
              {raw.lines
                .map((item) => `${String(item.line).padStart(6)}  ${item.text}`)
                .join("\n") || "No lines available."}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
