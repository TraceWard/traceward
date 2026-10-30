import { useMemo, useState } from 'react';
import type { Finding, Run } from './types';

export function readRoute() {
  const [path, query = ''] = window.location.hash.slice(1).split('?');
  const parts = path.split('/');
  const params = new URLSearchParams(query);
  const detailTab: 'evidence' | 'findings' = params.get('view') === 'evidence' ? 'evidence' : 'findings';
  return { page: parts[0] === 'agents' ? 'agents' : parts[0] === 'findings' ? 'findings' : 'runs',
    agentId: parts[0] === 'agents' ? parts[1] || '' : '',
    runId: parts[0] === 'runs' ? parts[1] || '' : '', findingId: params.get('finding') || '', detailTab };
}
export const runHref = (id: string, finding?: string) => `#runs/${encodeURIComponent(id)}${finding ? `?finding=${encodeURIComponent(finding)}` : ''}`;
export const runName = (run: Run) => run.name || run.goal || 'Unnamed run';
const harness = (run: Run) => run.source || 'unknown';
const label = (value: string) => value.replaceAll('_', ' ').replace(/\b\w/g, c => c.toUpperCase());
const timestamp = (value: number) => value ? new Date(value * 1000).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—';
const countEvents = (run: Run) => Object.values(run.event_counts).reduce((sum, n) => sum + n, 0);
const PAGE_SIZE = 25;

function PageControls({ page, total, setPage }: { page: number; total: number; setPage: (page: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  return <div className="table-pagination">
    <span>{total ? `${(page - 1) * PAGE_SIZE + 1}–${Math.min(page * PAGE_SIZE, total)} of ${total.toLocaleString()}` : '0 results'}</span>
    <div><button disabled={page <= 1} onClick={() => setPage(page - 1)}>Previous</button><span>Page {page} of {pages}</span><button disabled={page >= pages} onClick={() => setPage(page + 1)}>Next</button></div>
  </div>;
}
function Empty({ loaded, filtered, type }: { loaded: boolean; filtered: boolean; type: string }) {
  return <div className="table-empty" role="status"><h2>{!loaded ? `Loading ${type.toLowerCase()}…` : filtered ? 'No matching results' : `No ${type.toLowerCase()} yet`}</h2>
    <p>{!loaded ? 'Reading backend records.' : filtered ? 'Try a different search or clear the filters.' : type === 'Findings' ? 'Review findings will appear here. Cleared and incomplete assessments remain in each run’s assessment audit.' : 'Start an observed agent to see its run and investigate the evidence here.'}</p></div>;
}
function HarnessFilter({ runs, value, onChange }: { runs: Run[]; value: string; onChange: (v: string) => void }) {
  return <label>Harness<select aria-label="Harness" value={value} onChange={event => onChange(event.target.value)}><option value="all">All harnesses</option>{[...new Set(runs.map(harness))].sort().map(value => <option key={value} value={value}>{label(value)}</option>)}</select></label>;
}

export function RunsView({ runs, loaded }: { runs: Run[]; loaded: boolean }) {
  const [agentFilter, setAgentFilter] = useState('all');
  const [query, setQuery] = useState('');
  const [source, setSource] = useState('all');
  const [status, setStatus] = useState('all');
  const [findings, setFindings] = useState('all');
  const [sort, setSort] = useState('newest');
  const [page, setPage] = useState(1);
  const filtered = Boolean(query || source !== 'all' || status !== 'all' || findings !== 'all' || agentFilter !== 'all');
  const update = (setter: (s: string) => void) => (value: string) => { setter(value); setPage(1); };
  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return runs.filter(run => (!needle || [runName(run), run.goal, run.run_id, run.demo_case, run.agent_slug, run.agent_id].join(' ').toLowerCase().includes(needle))
      && (agentFilter === 'all' || (agentFilter === 'unattributed' ? !run.agent_id : run.agent_id === agentFilter))
      && (source === 'all' || harness(run) === source) && (status === 'all' || run.status === status)
      && (findings === 'all' || (findings === 'with' ? run.finding_count > 0 : run.finding_count === 0)))
      .sort((a, b) => sort === 'name' ? runName(a).localeCompare(runName(b)) : sort === 'findings' ? b.finding_count - a.finding_count || b.started_at - a.started_at : (sort === 'oldest' ? 1 : -1) * (a.started_at - b.started_at));
  }, [runs, query, source, status, findings, sort, agentFilter]);
  const currentPage = Math.min(page, Math.max(1, Math.ceil(visible.length / PAGE_SIZE)));
  return <div className="listing-page">
    <div className="listing-header"><div><h1>Agent Runs</h1><p>Explore agent activity and investigate what happened during each run.</p></div><span className="total-label">{runs.length.toLocaleString()} runs</span></div>
    <div className="list-summary"><span><b>{runs.filter(r => r.status === 'live').length}</b> live</span><span><b>{runs.filter(r => r.finding_count > 0).length}</b> with findings</span><span><b>{runs.filter(r => r.status === 'incomplete').length}</b> incomplete</span></div>
    <section className="table-panel" aria-label="Agent runs list">
      <div className="list-toolbar">
        <label className="search-field">Search runs<input type="search" placeholder="Search by name, goal or run ID…" value={query} onChange={e => update(setQuery)(e.target.value)} /></label>
        <HarnessFilter runs={runs} value={source} onChange={update(setSource)} />
        <label>Agent<select aria-label="Agent" value={agentFilter} onChange={e => update(setAgentFilter)(e.target.value)}><option value="all">All agents</option><option value="unattributed">Unattributed</option>{[...new Map(runs.filter(r => r.agent_id).map(r => [r.agent_id!, r.agent_slug])).entries()].map(([id, slug]) => <option key={id} value={id}>{slug}</option>)}</select></label>
        <label>Status<select aria-label="Status" value={status} onChange={e => update(setStatus)(e.target.value)}><option value="all">All statuses</option><option value="live">Live</option><option value="complete">Complete</option><option value="incomplete">Incomplete</option></select></label>
        <label>Findings<select aria-label="Findings" value={findings} onChange={e => update(setFindings)(e.target.value)}><option value="all">All runs</option><option value="with">With findings</option><option value="without">Without findings</option></select></label>
        <label>Sort by<select aria-label="Sort by" value={sort} onChange={e => update(setSort)(e.target.value)}><option value="newest">Newest first</option><option value="oldest">Oldest first</option><option value="name">Name</option><option value="findings">Most findings</option></select></label>
        {filtered && <button className="clear-filters" onClick={() => { setQuery(''); setSource('all'); setStatus('all'); setFindings('all'); setAgentFilter('all'); setPage(1); }}>Clear filters</button>}
      </div>
      <div className="table-scroll"><table className="data-table runs-table"><caption className="sr-only">Agent runs</caption><thead><tr><th scope="col">Harness</th><th scope="col">Name / authorised goal</th><th scope="col">Status</th><th scope="col">Findings</th><th scope="col">Events</th><th scope="col">Started</th><th scope="col"><span className="sr-only">Open run</span></th></tr></thead>
        <tbody>{visible.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE).map(run => <tr key={run.run_id} data-run-id={run.run_id} onClick={e => { if (!(e.target as HTMLElement).closest('a')) window.location.hash = runHref(run.run_id); }}>
          <td><span className="harness-tag">{label(harness(run))}</span></td>
          <td className="name-cell"><a href={runHref(run.run_id)} title={runName(run)}>{runName(run)}</a><small>{run.agent_slug || 'Unattributed'}</small>{(run.demo_case || run.legacy) && <small>{[run.demo_case, run.legacy && 'Historical'].filter(Boolean).join(' · ')}</small>}</td>
          <td><span className={`status-pill ${run.status}`}><i />{label(run.status)}</span>{run.analysis_state ? <small>Analysis {run.analysis_state}</small> : run.analysis_incomplete && <small>Analysis incomplete</small>}</td>
          <td><span className={run.finding_count ? 'finding-count has-findings' : 'finding-count'}>{run.finding_count}</span></td>
          <td className="numeric">{countEvents(run).toLocaleString()}</td><td className="date-cell"><time dateTime={new Date(run.started_at * 1000).toISOString()}>{timestamp(run.started_at)}</time></td><td aria-hidden="true" className="row-arrow">↗</td>
        </tr>)}</tbody></table></div>
      {!visible.length && <Empty loaded={loaded} filtered={filtered} type="Agent runs" />}
      <PageControls page={currentPage} total={visible.length} setPage={setPage} />
    </section>
    <p className="listing-note">Run status describes capture completion. A completed run or no findings does not establish that the agent behaved safely.</p>
  </div>;
}

export function FindingsView({ runs, findings, loaded }: { runs: Run[]; findings: (Finding & {run_id: string})[]; loaded: boolean }) {
  const [query, setQuery] = useState('');
  const [agentFilter, setAgentFilter] = useState('all');
  const [source, setSource] = useState('all');
  const [effect, setEffect] = useState('all');
  const [page, setPage] = useState(1);
  const runMap = useMemo(() => new Map(runs.map(run => [run.run_id, run])), [runs]);
  const needle = query.trim().toLowerCase();
  const visible = findings.filter(finding => {
    const run = runMap.get(finding.run_id);
    return (!needle || [finding.title, finding.message, finding.finding_id, finding.run_id, run && runName(run)].join(' ').toLowerCase().includes(needle))
      && (source === 'all' || (run && harness(run) === source)) && (effect === 'all' || finding.observed_effects.includes(effect))
      && (agentFilter === 'all' || (agentFilter === 'unattributed' ? !run?.agent_id : run?.agent_id === agentFilter));
  });
  const filtered = Boolean(query || source !== 'all' || effect !== 'all' || agentFilter !== 'all');
  const currentPage = Math.min(page, Math.max(1, Math.ceil(visible.length / PAGE_SIZE)));
  return <div className="listing-page">
    <div className="listing-header"><div><h1>Findings</h1><p>Review detected concerns across agent runs and follow the supporting evidence.</p></div><span className="total-label">{findings.length.toLocaleString()} findings</span></div>
    <div className="list-summary"><span><b>{new Set(findings.map(f => f.run_id)).size}</b> runs with findings</span><span>Current review findings only</span></div>
    <section className="table-panel" aria-label="Findings list">
      <div className="list-toolbar">
        <label className="search-field">Search findings<input type="search" placeholder="Search findings or agent runs…" value={query} onChange={e => { setQuery(e.target.value); setPage(1); }} /></label>
        <HarnessFilter runs={runs} value={source} onChange={v => { setSource(v); setPage(1); }} />
        <label>Agent<select aria-label="Agent" value={agentFilter} onChange={e => {setAgentFilter(e.target.value); setPage(1);}}><option value="all">All agents</option><option value="unattributed">Unattributed</option>{[...new Map(runs.filter(r => r.agent_id).map(r => [r.agent_id!, r.agent_slug])).entries()].map(([id, slug]) => <option key={id} value={id}>{slug}</option>)}</select></label>
        <label>Observed effect<select aria-label="Observed effect" value={effect} onChange={e => { setEffect(e.target.value); setPage(1); }}><option value="all">All effects</option>{[...new Set(findings.flatMap(f => f.observed_effects))].sort().map(value => <option key={value} value={value}>{label(value)}</option>)}</select></label>
        {filtered && <button className="clear-filters" onClick={() => { setQuery(''); setSource('all'); setEffect('all'); setAgentFilter('all'); setPage(1); }}>Clear filters</button>}
      </div>
      <div className="table-scroll"><table className="data-table findings-table"><caption className="sr-only">Review findings across runs</caption><thead><tr><th scope="col">Finding</th><th scope="col">Agent run</th><th scope="col">Harness</th><th scope="col">Observed effects</th><th scope="col">Detected</th><th scope="col"><span className="sr-only">Open investigation</span></th></tr></thead>
        <tbody>{visible.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE).map(finding => {
          const run = runMap.get(finding.run_id); const href = runHref(finding.run_id, finding.finding_id);
          return <tr key={`${finding.run_id}/${finding.finding_id}`} data-finding-id={finding.finding_id} onClick={e => { if (!(e.target as HTMLElement).closest('a')) window.location.hash = href; }}>
            <td className="name-cell"><a href={href}>{finding.title}</a><small className="review-label">Review required · revision {finding.revision}</small></td>
            <td className="finding-run-cell"><a href={href} title={run ? runName(run) : 'Run unavailable'}>{run ? runName(run) : 'Run unavailable'}</a><small>{run?.agent_slug || 'Unattributed'}</small></td>
            <td>{label(run ? harness(run) : 'unknown')}</td><td className="effects-cell">{finding.observed_effects.map(label).join(', ') || '—'}</td><td className="date-cell">{timestamp(finding.time)}</td><td aria-hidden="true" className="row-arrow">↗</td>
          </tr>;
        })}</tbody></table></div>
      {!visible.length && <Empty loaded={loaded} filtered={filtered} type="Findings" />}
      <PageControls page={currentPage} total={visible.length} setPage={setPage} />
    </section>
    <p className="listing-note">Findings need human review. Cleared, pending and inconclusive assessments are available in the run’s Assessment audit.</p>
  </div>;
}
