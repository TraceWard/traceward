import { useCallback, useEffect, useMemo, useState } from "react";

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
      raw_trace_ref?: string;
      hook_event?: string;
      apparent_command?: string;
      tool_use_id?: string;
      endpoint?: string;
      byte_count?: number;
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
  laya?: {
    status: string;
    reason?: string;
    model?: string;
    dimensions?: Record<string, number>;
  };
  revisions: Finding[];
};
type Raw = { source: string; lines: { line: number; text: string }[] };

const short = (value: string, size = 8) => value?.slice(0, size) || "—";
const date = (value?: number, millis = false) =>
  value ? new Date(value * (millis ? 1 : 1000)).toLocaleString() : "—";
const kind = (event: Event) => {
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
  if (kind(event) === "hook")
    return `${meta?.hook_event || "Hook"} · ${meta?.apparent_command || "tool call"}`;
  if (kind(event) === "process")
    return event.process?.cmd_line || event.process?.name || "Process launched";
  if (kind(event).startsWith("file"))
    return event.file?.path || "File operation";
  if (kind(event).startsWith("network"))
    return (
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
      const [eventData, findingData, processData] = await Promise.all([
        get<{ events: Event[]; next_before: number | null }>(
          `/api/runs/${runId}/events?limit=250`,
        ),
        get<{ findings: Finding[] }>(`/api/runs/${runId}/findings`),
        get<{ processes: Event[] }>(`/api/runs/${runId}/processes`),
      ]);
      setEvents(eventData.events);
      setProcesses(processData.processes);
      setOlder(eventData.next_before);
      setFindings(findingData.findings);
      setSelectedFinding((current) =>
        current && findingData.findings.some((f) => f.finding_id === current)
          ? current
          : findingData.findings[0]?.finding_id || "",
      );
      setError("");
    } catch (exc) {
      setError(`Cannot read run: ${String(exc)}`);
    }
  }, [runId]);
  useEffect(() => {
    void loadRuns();
    const stream = new EventSource("/api/stream");
    stream.onmessage = () => {
      void loadRuns();
    };
    stream.onerror = () => setError("Live connection interrupted; retrying…");
    return () => stream.close();
  }, [loadRuns]);
  useEffect(() => {
    setEvents([]);
    setProcesses([]);
    setFindings([]);
    setSelectedEvent(null);
    setSelectedFinding("");
    setEvidence([]);
    void loadRun();
  }, [runId, loadRun]);
  useEffect(() => {
    const stream = new EventSource("/api/stream");
    stream.onmessage = () => {
      void loadRun();
    };
    return () => stream.close();
  }, [loadRun]);
  const run = runs.find((item) => item.run_id === runId);
  const finding = findings.find((item) => item.finding_id === selectedFinding);
  useEffect(() => {
    if (!runId || !finding?.evidence_ids?.length) {
      setEvidence([]);
      return;
    }
    void get<{ events: Event[] }>(
      `/api/runs/${runId}/evidence?ids=${encodeURIComponent(finding.evidence_ids.join(","))}`,
    )
      .then((data) => setEvidence(data.events))
      .catch(() => setEvidence([]));
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
    const parents = new Map<number, number>();
    for (const event of processes) {
      const pid = event.process?.pid;
      const parent = event.process?.parent_process?.pid;
      if (pid && parent) parents.set(pid, parent);
    }
    const depth = (pid: number) => {
      let current = pid;
      let level = 0;
      const seen = new Set<number>();
      while (parents.has(current) && !seen.has(current) && level < 8) {
        seen.add(current);
        current = parents.get(current)!;
        level++;
      }
      return level;
    };
    return new Map(processes.map((event) => [event.metadata.uid, depth(event.process?.pid || 0)]));
  }, [processes]);
  const total = Object.values(run?.event_counts || {}).reduce(
    (a, b) => a + b,
    0,
  );
  const rawRef = selectedEvent?.unmapped?.traceward?.raw_trace_ref;
  const rawLine = rawRef && /^raw\.strace:(\d+)$/.exec(rawRef)?.[1];

  async function loadOlder() {
    if (!older || !runId) return;
    const result = await get<{ events: Event[]; next_before: number | null }>(
      `/api/runs/${runId}/events?limit=250&before=${older}`,
    );
    setEvents((current) => [...result.events, ...current]);
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
                <span>REVIEW FINDINGS</span>
                <strong>{run.finding_count}</strong>
                <small>Not confirmed violations</small>
              </div>
            </div>
            <div className="workspace-grid">
              <section className="trace-panel">
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
                        <time>{date(event.time, true).split(", ").pop()}</time>
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
                    {processes.map((event) => (
                      <button
                        key={event.metadata.uid}
                        style={{ paddingLeft: `${20 + (processDepths.get(event.metadata.uid) || 0) * 15}px` }}
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
                    {!processes.length && (
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
                        : "Findings & evaluation"}
                    </h2>
                  </div>
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
                    {rawLine && (
                      <button
                        className="raw-button"
                        onClick={() => void openRaw("strace", Number(rawLine))}
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
                            <div className="finding-alert">
                              <span className="finding-badge">
                                REVIEW REQUIRED
                              </span>
                              <h3>{finding.title}</h3>
                              <p>{finding.message}</p>
                              <small>
                                {finding.attribution} ·{" "}
                                {finding.observed_effects.join(" + ")}
                              </small>
                            </div>
                            <div className="section-label">
                              DECISION MODEL · {finding.laya?.status === "unavailable"
                                ? "UNAVAILABLE"
                                : finding.laya?.model || "PENDING"}
                            </div>
                            {finding.laya?.status === "scored" ? (
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
                                      <i>
                                        <em
                                          style={{ width: `${value * 100}%` }}
                                        />
                                      </i>
                                    </div>
                                  ))}
                                </div>
                                <p>
                                  This score is not a probability of
                                  misalignment or a confirmed violation.
                                </p>
                              </div>
                            ) : (
                              <div className="model-unavailable">
                                {finding.laya
                                  ? `Judgement unavailable (${finding.laya.reason || "no score"}).`
                                  : "Provisional finding. Waiting for Laya…"}{" "}
                                The observed evidence remains available.
                              </div>
                            )}
                            <div className="section-label">
                              CAUSAL EVIDENCE · {finding.evidence_ids.length}{" "}
                              IDS
                            </div>
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
                                    {item.laya?.status === "scored"
                                      ? item.laya.model?.includes("demo")
                                        ? "Simulated evaluator"
                                        : "Laya evaluation"
                                      : item.laya
                                        ? "Laya unavailable"
                                        : "Provisional evidence finding"}
                                  </span>
                                  <time>{date(item.time)}</time>
                                </div>
                              ))}
                            </div>
                            {finding.coverage_gaps?.length > 0 && (
                              <>
                                <div className="section-label">
                                  COVERAGE GAPS
                                </div>
                                <ul className="gaps">
                                  {finding.coverage_gaps.map((gap) => (
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
                        <div>✓</div>
                        <h3>No review findings</h3>
                        <p>
                          Nothing suspicious was detected within this run’s
                          coverage. This does not prove the agent was safe.
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
