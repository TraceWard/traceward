import { Fragment, useCallback, useEffect, useId, useMemo, useRef, useState } from "react";

import type { Run, Event, Finding, Raw } from "./types";
import { RunsView, FindingsView, readRoute } from "./views";
import ActivityChart from './ActivityChart';

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
  if (kind(event) === 'http_request') return `${String(detail?.method || 'HTTP')} ${String(detail?.url || 'request')}${detail?.status_code ? ` · ${detail.status_code}` : ''}`;
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


const citationLabel = (event: Event) => {
  const path = event.file?.path || event.unmapped?.traceward?.details?.path;
  const title = typeof path === 'string' ? path.split('/').filter(Boolean).pop() : eventTitle(event);
  return `${kind(event).replaceAll('_', ' ')} · ${title}`;
};

function EventDetails({selectedEvent, openRaw}: {selectedEvent: Event; openRaw: (source: string, line: number) => Promise<void>}) {
  const rawRef = selectedEvent?.unmapped?.traceward?.raw_trace_ref;
  const rawMatch = rawRef && /^raw\.(strace|gvisor\.jsonl):(\d+)$/.exec(rawRef);
  const rawLine = rawMatch && rawMatch[2];
  const rawSource = rawMatch && (rawMatch[1] === "strace" ? "strace" : "gvisor");
  return (
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
  );
}

function EvidenceCitations({ids, evidence, label, openRaw, chain = false}: {
  ids: string[]; evidence: Event[]; label: string;
  openRaw: (source: string, line: number) => Promise<void>; chain?: boolean;
}) {
  const [expanded, setExpanded] = useState<string | null>(null);
  const controls = useId();
  const returnPosition = useRef<{element: HTMLElement; top: number} | null>(null);
  const triggers = useRef(new Map<string, HTMLButtonElement>());
  const selected = evidence.find(item => item.metadata.uid === expanded);
  function close() {
    const trigger = expanded && triggers.current.get(expanded);
    const position = returnPosition.current;
    setExpanded(null);
    window.requestAnimationFrame(() => {
      if (trigger && trigger.isConnected) {
        if (position) position.element.scrollTop = position.top;
        trigger.focus({preventScroll: true});
      }
    });
  }
  function toggle(id: string) {
    if (expanded === id) { close(); return; }
    const element = triggers.current.get(id)?.closest('main');
    returnPosition.current = element ? {element, top: element.scrollTop} : null;
    setExpanded(id);
  }
  const details = selected && <section id={controls} className="inline-event-details" role="region" aria-label={`${label} event details`}>
      <div className="inline-event-heading"><strong>Event details</strong><button type="button" aria-label="Close evidence details" onClick={close}>Close details ×</button></div>
      <EventDetails selectedEvent={selected} openRaw={openRaw} />
    </section>;
  return <div className={chain ? 'evidence-chain' : 'evidence-citations'}>
    <div className={chain ? 'evidence-chain-links' : 'judge-citations'}>
      {ids.map((id, index) => {
        const item = evidence.find(event => event.metadata.uid === id);
        const title = item ? citationLabel(item) : 'Evidence unavailable';
        return <Fragment key={id}><button type="button" disabled={!item}
          ref={element => { if (element) triggers.current.set(id, element); else triggers.current.delete(id); }}
          aria-label={`${label} evidence ${title}`} aria-expanded={expanded === id}
          aria-controls={expanded === id ? controls : undefined}
          title={item ? `${eventTitle(item)} · Evidence ID: ${id}` : `Evidence ID: ${id}`}
          onClick={() => toggle(id)}>
          {chain ? <><span className="chain-index">{String(index + 1).padStart(2, '0')}</span>
            <span><b>{item ? eventTitle(item) : title}</b><small>{item ? kind(item).replaceAll('_', ' ') : ''} · {short(id, 16)}</small></span><span>{expanded === id ? '−' : '+'}</span></> : title}
        </button>{chain && expanded === id && details}</Fragment>;
      })}
    </div>
    {!chain && details}
  </div>;
}

export default function App() {
  const [runs, setRuns] = useState<Run[]>([]);
  const [route, setRoute] = useState(readRoute);
  const runId = route.runId;
  const [detailTab, setDetailTab] = useState<'evidence' | 'findings'>(route.detailTab);
  const [allFindings, setAllFindings] = useState<(Finding & {run_id: string})[]>([]);
  const [listsLoaded, setListsLoaded] = useState(false);
  const [events, setEvents] = useState<Event[]>([]);
  const [processes, setProcesses] = useState<Event[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [assessmentAudit, setAssessmentAudit] = useState(false);
  const [evidence, setEvidence] = useState<Event[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<string>("");
  const [selectedEvent, setSelectedEvent] = useState<Event | null>(null);
  const [tab, setTab] = useState<"timeline" | "processes">("timeline");
  const [eventOrder, setEventOrder] = useState<'newest' | 'oldest'>('newest');
  const [filter, setFilter] = useState("evidence");
  const [view, setView] = useState<"combined" | "hooks" | "runtime">(
    "combined",
  );
  const [error, setError] = useState("");
  const [raw, setRaw] = useState<Raw | null>(null);
  const [older, setOlder] = useState<number | null>(null);
  const [evaluations, setEvaluations] = useState<{finding_id: string; revision: number; packet: unknown; judgement: unknown}[]>([]);
  const [loadedRun, setLoadedRun] = useState("");
  const [pendingAssessments, setPendingAssessments] = useState(0);
  const activeRun = useRef(runId);
  const paginationStarted = useRef(false);
  const eventInspector = useRef<HTMLElement | null>(null);
  const eventRows = useRef(new Map<string, HTMLButtonElement>());
  activeRun.current = runId;

  const loadRuns = useCallback(async () => {
    try {
      const [data, reviews] = await Promise.all([
        get<{ runs: Run[] }>("/api/runs"),
        get<{ findings: (Finding & {run_id: string})[] }>("/api/findings"),
      ]);
      setRuns(data.runs);
      setAllFindings(reviews.findings);
      setListsLoaded(true);
      setError("");
    } catch (exc) {
      setError(`Cannot read runs: ${String(exc)}`);
    }
  }, []);
  const loadRun = useCallback(async () => {
    if (!runId) return;
    try {
      const [eventData, findingData, processData, evaluationData, assessmentData] = await Promise.all([
        get<{ events: Event[]; next_before: number | null }>(
          `/api/runs/${runId}/events?limit=250`,
        ),
        get<{ findings?: Finding[]; assessments?: Finding[] }>(`/api/runs/${runId}/${assessmentAudit ? 'assessments' : 'findings'}`),
        get<{ processes: Event[] }>(`/api/runs/${runId}/processes`),
        get<{ evaluations: typeof evaluations }>(`/api/runs/${runId}/evaluations`),
        get<{ assessments: Finding[] }>(`/api/runs/${runId}/assessments`),
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
      setPendingAssessments(assessmentData.assessments.filter(a => a.status === 'provisional').length);
      setLoadedRun(runId);
      setSelectedFinding((current) =>
        current && visible.some((f) => f.finding_id === current)
          ? current
          : visible.find(f => f.finding_id === route.findingId)?.finding_id || visible[0]?.finding_id || "",
      );
      setError("");
    } catch (exc) {
      setError(`Cannot read run: ${String(exc)}`);
    }
  }, [runId, assessmentAudit, route.findingId]);
  useEffect(() => {
    const navigate = () => { setRoute(readRoute()); setAssessmentAudit(false); setRaw(null); };
    window.addEventListener("hashchange", navigate);
    return () => window.removeEventListener("hashchange", navigate);
  }, []);
  useEffect(() => { setDetailTab(route.detailTab); }, [route]);
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
    setLoadedRun("");
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
    if (!runId) return;
    const stream = new EventSource("/api/stream");
    stream.onmessage = () => {
      void loadRun();
    };
    const timer = window.setInterval(() => void loadRun(), 2000);
    return () => { stream.close(); window.clearInterval(timer); };
  }, [loadRun, runId]);
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
  const orderedEvents = useMemo(() => eventOrder === 'newest' ? [...shown].reverse() : shown, [shown, eventOrder]);
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

  function selectDetailTab(value: 'evidence' | 'findings') {
    setDetailTab(value);
    setSelectedEvent(null);
    const [path, query = ''] = window.location.hash.split('?');
    const params = new URLSearchParams(query);
    params.set('view', value);
    window.history.replaceState(null, '', `${path}?${params}`);
  }

  function inspectEvent(event: Event) {
    setSelectedEvent(event);
    if (window.matchMedia('(max-width: 1100px)').matches) {
      window.requestAnimationFrame(() => {
        if (activeRun.current !== runId) return;
        eventInspector.current?.scrollIntoView({block: 'start'});
        eventInspector.current?.focus({preventScroll: true});
      });
    }
  }

  function returnToEvent() {
    if (!selectedEvent) return;
    const row = eventRows.current.get(selectedEvent.metadata.uid);
    row?.scrollIntoView({block: 'center'});
    row?.focus({preventScroll: true});
  }

  return (
    <div className="app">
      <aside className="sidebar">
        <a className="brand" href="#runs" aria-label="TraceWard home">
          <div className="brand-mark">T</div>
          <strong>TraceWard</strong>
        </a>
        <nav className="side-section" aria-label="Main navigation">
          <span>OBSERVABILITY</span>
          <a href="#runs" className={route.page === "runs" ? "nav-link active" : "nav-link"} aria-current={route.page === "runs" ? "page" : undefined}>
            <span aria-hidden="true">▦</span> Agent Runs <em>{runs.length}</em>
          </a>
          <a href="#findings" className={route.page === "findings" ? "nav-link active" : "nav-link"} aria-current={route.page === "findings" ? "page" : undefined}>
            <span aria-hidden="true">⚑</span> Findings <em>{allFindings.length}</em>
          </a>
        </nav>
        <div className="side-footer">Local workspace<small>Read-only · Observe-only</small></div>
      </aside>
      <main className="main">
        <header className="topbar">
          <div className="breadcrumb">
            <a href={route.page === "findings" ? "#findings" : "#runs"}>{route.page === "findings" ? "Findings" : "Agent Runs"}</a>
            {runId && <><span>/</span><b>Investigation</b></>}
          </div>
          <span className="local-label">Local workspace</span>
        </header>
        {error && <div className="error-banner">{error}</div>}
        <div hidden={Boolean(runId) || route.page !== "runs"}><RunsView runs={runs} loaded={listsLoaded} /></div>
        <div hidden={Boolean(runId) || route.page !== "findings"}><FindingsView runs={runs} findings={allFindings} loaded={listsLoaded} /></div>
        {!runId ? null : !run ? (
          <div className="welcome"><h1>{listsLoaded ? "Run not found" : "Loading investigation…"}</h1>
            <p>{listsLoaded ? "This run is not available in the current workspace." : "Reading local evidence."}</p>
            <a href="#runs">Back to Agent Runs</a>
          </div>
        ) : (
          <>
            <div className="content-header">
              <div>
                <div className="eyebrow">
                  RUN{" "}
                  <span className={`status-label ${run.status}`}>
                    {run.status}
                  </span>
                </div>
                <h1>Agent Run Investigation</h1>
                <p>
                  Started {date(run.started_at)} · {total.toLocaleString()}{" "}
                  recorded events
                </p>
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
            {pendingAssessments > 0 && <p className="analysis-status" role="status">Assessing {pendingAssessments} observed {pendingAssessments === 1 ? 'effect' : 'effects'}… Findings appear as review completes; the agent can keep running.</p>}
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
            <ActivityChart key={runId} runId={runId} live={run.status === 'live'} onFinding={id => {
              setSelectedFinding(id); setAssessmentAudit(false);
              window.location.hash = `runs/${runId}?finding=${id}&view=findings`;
            }} />
            <div className="investigation-tabs" role="tablist" aria-label="Run investigation" onKeyDown={event => {
              if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
              event.preventDefault();
              const next = event.key === 'Home' ? 'findings' : event.key === 'End' ? 'evidence' : detailTab === 'evidence' ? 'findings' : 'evidence';
              selectDetailTab(next);
              document.getElementById(`run-tab-${next}`)?.focus();
            }}>
              <button id="run-tab-findings" type="button" role="tab" aria-selected={detailTab === 'findings'} aria-controls="investigation-panel" tabIndex={detailTab === 'findings' ? 0 : -1} onClick={() => selectDetailTab('findings')}>Findings <span aria-hidden="true">{run.finding_count}</span></button>
              <button id="run-tab-evidence" type="button" role="tab" aria-selected={detailTab === 'evidence'} aria-controls="investigation-panel" tabIndex={detailTab === 'evidence' ? 0 : -1} onClick={() => selectDetailTab('evidence')}>Evidence Stream</button>
            </div>
            <div id="investigation-panel" role="tabpanel" aria-labelledby={`run-tab-${detailTab}`} className={`workspace-grid ${detailTab === 'evidence' && selectedEvent ? 'has-event-details' : ''}`}>
              <section className="trace-panel" hidden={detailTab !== 'evidence'} data-loaded-events={events.length}>
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
                  <div className="event-filters">
                  {tab === 'timeline' && <select aria-label="Event order" value={eventOrder} onChange={event => setEventOrder(event.target.value as 'newest' | 'oldest')}>
                    <option value="newest">Newest first</option>
                    <option value="oldest">Oldest first</option>
                  </select>}
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
                    <option value="http_request">HTTP requests</option>
                    <option value="finding">Findings</option>
                    <option value="coverage">Coverage</option>
                  </select>
                  </div>
                </div>
                {tab === "timeline" ? (
                  <div className="event-list">
                    {eventOrder === 'oldest' && older && (filter !== "evidence" || !finding) && (
                      <button
                        className="load-more"
                        onClick={() => void loadOlder()}
                      >
                        Load earlier events
                      </button>
                    )}
                    {orderedEvents.map((event) => (
                      <button
                        key={event.metadata.uid}
                        ref={element => { if (element) eventRows.current.set(event.metadata.uid, element); else eventRows.current.delete(event.metadata.uid); }}
                        data-event-id={event.metadata.uid}
                        data-kind={kind(event)}
                        data-time={event.time}
                        className={`event-row ${selectedEvent?.metadata.uid === event.metadata.uid ? "picked" : ""}`}
                        onClick={() => {
                          inspectEvent(event);
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
                    {eventOrder === 'newest' && older && (filter !== 'evidence' || !finding) && <button className="load-more" onClick={() => void loadOlder()}>Load earlier events</button>}
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
                        ref={element => { if (element) eventRows.current.set(event.metadata.uid, element); else eventRows.current.delete(event.metadata.uid); }}
                        data-depth={processDepths.get(event.metadata.uid) || 0}
                        onClick={() => {
                          inspectEvent(event);
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
              <aside ref={eventInspector} tabIndex={selectedEvent ? -1 : undefined} aria-label={selectedEvent ? 'Event details' : undefined} className="inspector" hidden={detailTab === 'evidence' && !selectedEvent}>
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
                  {selectedEvent && <div className="event-detail-actions">
                    {detailTab === 'evidence' && <button type="button" onClick={returnToEvent}>Back to selected event</button>}
                    <button
                      className="close"
                      aria-label="Close event details"
                      onClick={() => setSelectedEvent(null)}
                    >
                      ×
                    </button>
                  </div>}
                </div>
                {selectedEvent ? (
                  <EventDetails selectedEvent={selectedEvent} openRaw={openRaw} />
                ) : (
                  <div className="inspector-scroll">
                    {findings.length ? (
                      <div className="finding-layout">
                        <nav className="finding-tabs" aria-label={assessmentAudit ? "Assessments in this run" : "Findings in this run"}>
                          <div className="finding-list-heading">{findings.length} {assessmentAudit ? 'assessments' : findings.length === 1 ? 'finding' : 'findings'}</div>
                          {findings.map((item, index) => (
                            <button
                              key={item.finding_id}
                              data-finding-selector={item.finding_id}
                              className={selectedFinding === item.finding_id ? "on" : ""}
                              aria-pressed={selectedFinding === item.finding_id}
                              onClick={() => {
                                setSelectedFinding(item.finding_id);
                                if (!assessmentAudit) {
                                  const [path, query = ''] = window.location.hash.split('?');
                                  const params = new URLSearchParams(query);
                                  params.set('finding', item.finding_id);
                                  params.set('view', 'findings');
                                  window.history.replaceState(null, '', `${path}?${params}`);
                                }
                              }}
                            >
                              <span className="finding-number" aria-hidden="true">{index + 1}</span>
                              <span className="finding-option">
                                <strong>{item.title}</strong>
                                <small>{assessmentAudit ? item.status.replaceAll('_', ' ') : item.observed_effects.map(effect => effect.replaceAll('_', ' ')).join(', ')} · {item.evidence_ids.length} evidence events</small>
                              </span>
                            </button>
                          ))}
                        </nav>
                        {finding && (
                          <div className="finding-detail">
                            <p className="finding-position">{assessmentAudit ? 'Assessment' : 'Finding'} {findings.indexOf(finding) + 1} of {findings.length}</p>
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
                            {finding.assessment_note && <p className="assessment-note">{finding.assessment_note}</p>}
                            {finding.analysis_window && <p className="window-status">Rolling {finding.analysis_window.duration_seconds}-second observation window with relevant earlier causal evidence. {finding.analysis_window.agent_finished ? 'Final session context.' : 'Assessed while the session was running; new evidence feeds later windows.'}</p>}
                            <div className="section-label">
                              DECISION MODEL · {finding.judge?.status === "unavailable"
                                ? "UNAVAILABLE"
                                : finding.judge?.model || "PENDING"}
                            </div>
                            {finding.judge?.status === "assessed" ? (
                              <div className="score-card structured-assessment">
                                <div className="score-top">
                                  <div><span>MODEL VERDICT</span><strong>{finding.judge.disposition?.replaceAll("_", " ")}</strong></div>
                                  <span className="score-tag">{finding.judge.model?.includes("demo") ? "SIMULATED EVALUATOR" : finding.judge.contract_version === 'goal-effects-live-v1' ? 'STRUCTURED LIVE REVIEW' : "STRUCTURED MODEL REVIEW"}</span>
                                </div>
                                <p className="judge-rationale">{finding.judge.rationale}</p>
                                {finding.assessment && <div className="assessment-facets">
                                  {Object.entries(finding.assessment).map(([name, facet]) => <section key={name} className="assessment-facet" data-status={facet.status}>
                                    <div><strong>{name.replaceAll('_', ' ')}</strong><span>{facet.status.replaceAll('_', ' ')}</span></div>
                                    <p>{facet.summary}</p>
                                    <EvidenceCitations key={`${finding.finding_id}:${finding.revision}:${name}`} ids={facet.evidence_ids} evidence={evidence} label={name.replaceAll('_', ' ')} openRaw={openRaw} />
                                  </section>)}
                                </div>}
                                {finding.verified_claims?.length ? <div className="supported-facts"><strong>Evidence predicates checked</strong>
                                  <ul>{finding.verified_claims.map((claim, i) => <li key={i}>{claim.fact_type.replaceAll('_', ' ')} · {claim.evidence_ids.map(id => short(id)).join(', ')}</li>)}</ul>
                                  <p>These checks validate typed evidence predicates; model interpretations can still be wrong.</p>
                                </div> : null}
                                <EvidenceCitations key={`${finding.finding_id}:${finding.revision}:judge`} ids={finding.judge.cited_evidence_ids || []} evidence={evidence} label="Judge" openRaw={openRaw} />
                                <p>No numerical risk score. This verdict is not a confirmed violation or proof of safety.</p>
                                <p>Experimental judgement: validation covers reviewed cases; production accuracy is not established.</p>
                              </div>
                            ) : finding.judge?.status === "scored" ? (
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
                                    {finding.judge?.model?.includes("demo") ? "SIMULATED EVALUATOR" : "MODEL REVIEW"}
                                  </span>
                                </div>
                                <div className="score-bars">
                                  {Object.entries(
                                    finding.judge.dimensions || {},
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
                                {finding.judge.semantic_accuracy_validated === false && (
                                  <p>Experimental judgement: semantic accuracy is not validated. Historical scores are uncalibrated and do not establish production accuracy.</p>
                                )}
                                {run.legacy && <p>Historical assessment: limited context and simulated scores have not been revalidated.</p>}
                              </div>
                            ) : (
                              <div className="model-unavailable">
                                {finding.judge
                                  ? `Judgement unavailable (${finding.judge.reason || "no score"}${finding.judge.validation_error ? `: ${finding.judge.validation_error}` : ''}).`
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
                            <EvidenceCitations key={`${finding.finding_id}:${finding.revision}:causal`} ids={finding.evidence_ids} evidence={evidence} label="Causal" openRaw={openRaw} chain />
                            <details className="finding-metadata">
                              <summary>Technical details</summary>
                              <div className="detail-pair"><span>Finding ID</span><code>{finding.finding_id}</code></div>
                              <div className="detail-pair"><span>Revision</span><b>{finding.revision}</b></div>
                            </details>
                            <div className="section-label">
                              REVISION HISTORY
                            </div>
                            <div className="revision-list">
                              {finding.revisions.map((item) => (
                                <div key={item.revision}>
                                  <b>r{item.revision}</b>
                                  <span>
                                    {item.judge?.status === "assessed" ? "Structured model assessment" : item.judge?.status === "scored"
                                      ? item.judge.model?.includes("demo")
                                        ? "Simulated evaluator"
                                        : "Model evaluation"
                                      : item.judge
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
                          </div>
                        )}
                      </div>
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
