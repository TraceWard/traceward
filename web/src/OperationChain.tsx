import {useId, useRef, useState, type ReactNode} from 'react';
import type {Event, OperationChain} from './types';

function OperationIcon({kind}: {kind: string}) {
  const path = kind === 'hook' ? 'm5 7 4 5-4 5m7 0h7' : kind === 'process'
    ? 'M5 5h14v14H5zM9 1v4m6-4v4M9 19v4m6-4v4M1 9h4m-4 6h4m14-6h4m-4 6h4'
    : kind.startsWith('network') ? 'M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0ZM3 12h18M12 3c-5 5-5 13 0 18 5-5 5-13 0-18'
    : 'M6 3h8l4 4v14H6zM14 3v5h4M9 12h6m-6 4h6';
  return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={path}/></svg>;
}

export default function OperationChainView({chain, error, titleForEvent, renderDetails}: {
  chain: OperationChain | null; error: string;
  titleForEvent: (event: Event) => string;
  renderDetails: (event: Event, close: () => void) => ReactNode;
}) {
  const [branches, setBranches] = useState(new Set<string>());
  const [selected, setSelected] = useState<string | null>(null);
  const buttons = useRef(new Map<string, HTMLButtonElement>());
  const position = useRef<{element: HTMLElement; top: number} | null>(null);
  const controls = useId();
  function close() {
    const button = selected ? buttons.current.get(selected) : null;
    setSelected(null);
    window.requestAnimationFrame(() => {
      if (position.current) position.current.element.scrollTop = position.current.top;
      button?.focus({preventScroll: true});
    });
  }
  function inspect(id: string) {
    if (selected === id) { close(); return; }
    const main = buttons.current.get(id)?.closest('main');
    position.current = main ? {element: main, top: main.scrollTop} : null;
    setSelected(id);
  }
  const nodes = new Map(chain?.nodes.map(node => [node.id, node]) || []);
  const incoming = new Map(chain?.edges.map(edge => [edge.target, edge]) || []);
  const children = new Map<string, string[]>();
  for (const edge of chain?.edges || []) children.set(edge.source, [...(children.get(edge.source) || []), edge.target]);
  const origin = Math.min(...(chain?.nodes.map(node => node.event.time) || [0]));
  function render(id: string): ReactNode {
    const node = nodes.get(id);
    if (!node) return null;
    const edge = incoming.get(id);
    const next = children.get(id) || [];
    const main = next.filter(key => nodes.get(key)?.on_path);
    const related = next.filter(key => !nodes.get(key)?.on_path);
    const scripts = node.event.unmapped?.traceward?.script_paths || [];
    const processPid = node.event.process?.pid || node.event.actor?.process?.pid || node.event.unmapped?.traceward?.pid;
    const outcome = node.event.unmapped?.traceward?.operation_status;
    return <li className="operation-step" key={id} data-operation-id={id}>
      {edge && <div className="operation-link" data-basis={edge.basis}>
        <span>{edge.label}</span><small>{edge.basis === 'observed' ? 'Observed' : 'Inferred'}</small>
      </div>}
      <button type="button" className="operation-card" data-finding-effect={node.is_consequential}
        ref={element => {if (element) buttons.current.set(id, element); else buttons.current.delete(id);}}
        aria-label={`Inspect operation ${titleForEvent(node.event)}`} aria-expanded={selected === id}
        aria-controls={selected === id ? controls : undefined} onClick={() => inspect(id)}>
        <span className="operation-icon"><OperationIcon kind={node.kind}/></span>
        <span className="operation-body">
          <span className="operation-type">{node.kind === 'hook' ? 'Agent tool call' : node.kind.replaceAll('_', ' ')}
            {node.is_consequential && <em>Finding effect</em>}</span>
          <strong>{titleForEvent(node.event)}</strong>
          {scripts.length > 0 && <span className="operation-scripts">{scripts.join(' · ')}</span>}
          <span className="operation-meta">{processPid ? `PID ${processPid} · ` : ''}{outcome ? `${outcome} · ` : ''}
            <time dateTime={new Date(node.event.time).toISOString()} title={new Date(node.event.time).toLocaleString()}>+{((node.event.time-origin)/1000).toFixed(3)}s</time>
            <span className="operation-evidence-id"> · {id.slice(0, 12)}</span>
          </span>
        </span><span className="operation-expand" aria-hidden="true">{selected === id ? '−' : '+'}</span>
      </button>
      {selected === id && <section id={controls} role="region" aria-label="Operation event details" className="inline-event-details operation-details">
        {renderDetails(node.event, close)}
      </section>}
      {related.length > 0 && <div className="operation-branch">
        <button type="button" className="operation-branch-toggle" aria-expanded={branches.has(id)} onClick={() => setBranches(current => {
          const updated = new Set(current); if (updated.has(id)) updated.delete(id); else updated.add(id); return updated;
        })}><span aria-hidden="true">{branches.has(id) ? '−' : '+'}</span> {related.length} related {related.length === 1 ? 'branch' : 'branches'}</button>
        {branches.has(id) && <ol className="operation-related">{related.map(render)}</ol>}
      </div>}
      {main.length > 0 && <ol className="operation-children">{main.map(render)}</ol>}
    </li>;
  }
  return <section className="operation-chain" aria-label="How this happened">
    <div className="operation-heading"><div><h4>How this happened</h4><p>The recorded path to the finding effect.</p></div>
      <span className="operation-key"><i/> Observed <i className="inferred"/> Inferred</span></div>
    {!chain && <p className="operation-notice" role="status">{error || 'Loading operation evidence…'}</p>}
    {chain && <>
      {error && <p className="operation-notice" role="status">{error}</p>}
      {chain.nodes.length > 0 ? <ol className="operation-roots">{chain.roots.map(render)}</ol> : <p className="operation-notice">No operation path can be reconstructed from the retained evidence.</p>}
      {chain.gaps.length > 0 && <div className="operation-gaps"><strong>Evidence gaps</strong><ul>{chain.gaps.map(gap => <li key={gap}>{gap}</li>)}</ul></div>}
      {chain.associations.length > 0 && <p className="operation-notice">Additional resource or temporal associations remain in the supporting evidence. They do not establish execution ancestry or payload flow.</p>}
      <p className="operation-footnote">Related branches show assessed evidence. Ancestors provide context; the chain does not establish intent.</p>
    </>}
  </section>;
}
