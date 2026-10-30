import {useEffect, useRef, useState} from 'react';
import type {Run} from './types';
import {RunsView} from './views';

type Agent = {agent_id: string; agent_slug: string; goal: string; created_at: number};

function CopyIcon() {
  return <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/></svg>;
}

export default function AgentsView({agentId, runs, runsLoaded}: {agentId: string; runs: Run[]; runsLoaded: boolean}) {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState('');
  const [goal, setGoal] = useState('');
  const [slug, setSlug] = useState('');
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState('');
  const [copied, setCopied] = useState('');
  const createDialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {setCopied('');}, [agentId]);
  useEffect(() => {
    let active = true;
    const refresh = async () => {
      try {
        const response = await fetch('/api/agents', {cache: 'no-store'});
        if (!response.ok) throw Error(`Backend returned ${response.status}`);
        const data = await response.json();
        if (active) {setAgents(data.agents); setLoaded(true); setError('');}
      } catch (exc) {if (active) setError(`Cannot read agents: ${String(exc)}`);}
    };
    void refresh();
    const timer = setInterval(() => void refresh(), 2000);
    return () => {active = false; clearInterval(timer);};
  }, []);
  const create = async (event: React.FormEvent) => {
    event.preventDefault(); setCreating(true); setCreateError('');
    try {
      const response = await fetch('/api/agents', {method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({goal, ...(slug ? {agent_slug: slug} : {})})});
      const data = await response.json();
      if (!response.ok) throw Error(data.detail || 'Could not create agent');
      setAgents(current => [data, ...current]); setGoal(''); setSlug('');
      createDialog.current?.close();
      window.location.hash = `agents/${data.agent_id}`;
    } catch (exc) {setCreateError(String(exc));}
    finally {setCreating(false);}
  };
  const copy = async (text: string, label: string) => {
    try {
      if (navigator.clipboard) await navigator.clipboard.writeText(text);
      else {
        const input = document.createElement('textarea'); input.value = text;
        document.body.append(input); input.select();
        const success = document.execCommand('copy'); input.remove();
        if (!success) throw Error('Copy unavailable; select the text instead.');
      }
      setCopied(`${label} copied`);
    } catch (exc) {setCopied(String(exc));}
  };
  const agent = agents.find(item => item.agent_id === agentId);
  const command = agent ? `traceward run --traceward-url ${window.location.origin} --agent-slug ${agent.agent_slug} <agent> [agent args]` : '';
  return <div className="listing-page agents-page">
    {error && <div className="error-banner" role="alert">{error}</div>}
    {agentId ? !agent ? <div className="welcome"><h1>{loaded ? 'Agent not found' : error ? 'Agent unavailable' : 'Loading agent…'}</h1><a href="#agents">Back to Agents</a></div> : <>
      <a className="agent-back" href="#agents">← All agents</a>
      <div className="listing-header"><div><h1>{agent.agent_slug}</h1><p>Registered agent and its observed runs.</p></div></div>
      <section className="agent-card" aria-label="Agent details">
        <dl><dt>Agent ID</dt><dd><code>{agent.agent_id}</code><button className="copy-icon" aria-label="Copy agent ID" title="Copy agent ID" onClick={() => void copy(agent.agent_id, 'Agent ID')}><CopyIcon/></button></dd>
          <dt>Agent slug</dt><dd><code>{agent.agent_slug}</code><button className="copy-icon" aria-label="Copy agent slug" title="Copy agent slug" onClick={() => void copy(agent.agent_slug, 'Agent slug')}><CopyIcon/></button></dd>
        </dl>
        <div className="agent-goal"><h2>Configured goal</h2><p>{agent.goal}</p><small>This goal takes precedence over CLI goal flags and is frozen for each run.</small></div>
        <div className="agent-command"><code>{command}</code><button className="copy-icon" aria-label="Copy command" title="Copy command" onClick={() => void copy(command, 'Command')}><CopyIcon/></button></div>
        <p className="agent-command-help">Replace <code>&lt;agent&gt;</code> with <code>codex</code> or <code>pi</code>, then add its normal arguments. The registered identity is shared across integrations.</p>
        {copied && <p className="copy-status" role="status">{copied}</p>}
      </section>
      <section className="agent-runs" aria-label="Agent runs"><RunsView key={agent.agent_id} runs={runs.filter(run => run.agent_id === agent.agent_id)} loaded={runsLoaded} /></section>
    </> : <>
      <div className="listing-header"><div><h1>Agents</h1><p>Register an identity and authorised goal, then select it when starting a run.</p></div><div className="agents-actions"><span>{loaded ? `${agents.length} agents` : error ? 'Unavailable' : 'Loading…'}</span><button className="primary-button" onClick={() => {setCreateError(''); createDialog.current?.showModal();}}>Create agent</button></div></div>
      <dialog className="agent-dialog" ref={createDialog} aria-labelledby="create-agent-title">
      <form className="agent-form" onSubmit={event => void create(event)}>
        <h2 id="create-agent-title">Create agent</h2>
        {createError && <div className="error-banner" role="alert">{createError}</div>}
        <label>Agent slug <small>Optional; generated when left empty</small><input aria-label="Agent slug" value={slug} onChange={event => setSlug(event.target.value)} placeholder="release-reviewer" maxLength={100} /></label>
        <label>Authorised goal<textarea aria-label="Authorised goal" value={goal} onChange={event => setGoal(event.target.value)} required rows={5} placeholder="Describe the authorised task and any explicit constraints." /></label>
        <div className="agent-form-actions"><button type="button" disabled={creating} onClick={() => createDialog.current?.close()}>Cancel</button><button type="submit" disabled={creating || !goal.trim()}>{creating ? 'Creating…' : 'Create agent'}</button></div>
      </form>
      </dialog>
      <section className="table-panel" aria-label="Registered agents"><div className="table-scroll"><table className="data-table agents-table"><thead><tr><th>Agent</th><th>Goal</th><th>Runs</th></tr></thead>
        <tbody>{agents.map(item => <tr key={item.agent_id} onClick={event => {if (!(event.target as HTMLElement).closest('a')) window.location.hash = `agents/${item.agent_id}`;}}><td><a href={`#agents/${item.agent_id}`}>{item.agent_slug}</a><small>{item.agent_id}</small></td><td>{item.goal}</td><td>{runsLoaded ? runs.filter(run => run.agent_id === item.agent_id).length : '—'}</td></tr>)}</tbody></table></div>
        {!agents.length && <p className="agent-empty">{loaded ? 'No registered agents yet. Create your first agent above.' : error ? 'Agent list unavailable. Reconnecting…' : 'Loading agents…'}</p>}
      </section>
    </>}
  </div>;
}
