"""Read-only operation paths reconstructed from retained, source-labelled evidence."""
from __future__ import annotations

from collections import defaultdict


def build_operation_chain(finding: dict, events: list[dict]) -> dict:
    def meta(e):
        return e.get('unmapped', {}).get('traceward', {})

    def kind(e):
        from .dashboard import _kind
        return _kind(e)

    def order(e):
        return e.get('time', 0), e.get('index_id', 0), e['metadata']['uid']

    def pid(e):
        return (e.get('process') or e.get('actor', {}).get('process') or {}).get('pid', meta(e).get('pid'))

    events = sorted(events, key=order)
    by_id = {e['metadata']['uid']: e for e in events}
    evidence_ids = list(dict.fromkeys(finding.get('evidence_ids', [])))
    triggers = set(finding.get('consequential_evidence_ids', []))
    gaps, nodes, edges = [], {}, {}
    raw_links = finding.get('causal_links') or []
    links = [link for link in raw_links if isinstance(link, dict) and isinstance(link.get('relation'), str)] if isinstance(raw_links, list) else []
    associations = [link for link in links
                    if link.get('relation') in {'earlier_run_access', 'same_content_hash', 'same_sampled_resource_version'}]

    def gap(text):
        if text not in gaps:
            gaps.append(text)

    processes, identities, exits = defaultdict(list), defaultdict(set), defaultdict(list)
    for e in events:
        if kind(e) == 'process':
            key = meta(e).get('process_key')
            if key:
                processes[key].append(e)
            identities[pid(e)].add(key)
        elif kind(e) == 'process_exit' and meta(e).get('process_key'):
            exits[meta(e)['process_key']].append(e)

    def active(key, at):
        candidates = [p for p in processes.get(key, []) if order(p) <= order(at)]
        if not candidates:
            return None
        selected = candidates[-1]
        if any(order(selected) <= order(exit_event) <= order(at) for exit_event in exits[key]):
            return None
        return selected

    def actor(e):
        key = meta(e).get('process_key')
        if key:
            return active(key, e), 'observed'
        # Legacy PIDs are usable only when the retained run has one identity.
        keys = identities.get(pid(e), set())
        if len(keys) != 1:
            return None, 'inferred'
        key = next(iter(keys))
        if key:
            return active(key, e), 'inferred'
        candidates = [p for p in events if kind(p) == 'process' and pid(p) == pid(e)]
        return (candidates[0] if len(candidates) == 1 and order(candidates[0]) <= order(e) else None), 'inferred'

    recorded_parents = defaultdict(set)
    for link in links:
        if link['relation'] == 'process_parent':
            child, parent_id = link.get('evidence_id'), link.get('parent_evidence_id')
            if isinstance(child, str) and isinstance(parent_id, str):
                recorded_parents[child].add(parent_id)
    anchors, native, conflicting = {}, {}, set()
    uncertain = finding.get('attribution') == 'uncertain'
    for link in links:
        if uncertain:
            continue
        hook_id = link.get('hook_evidence_id')
        hook = by_id.get(hook_id) if isinstance(hook_id, str) else None
        if not hook or kind(hook) != 'hook' or meta(hook).get('hook_event') != 'PreToolUse':
            continue
        if finding.get('tool_use_id') and meta(hook).get('tool_use_id') != finding['tool_use_id']:
            continue
        if link.get('relation') == 'hook_command_time_match':
            target_id = link.get('process_evidence_id')
            target = by_id.get(target_id) if isinstance(target_id, str) else None
            if target and kind(target) == 'process':
                target_id = target['metadata']['uid']
                if target_id in anchors and anchors[target_id] != hook:
                    conflicting.add(target_id)
                anchors[target_id] = hook
        elif link.get('relation') == 'hook_resource_time_match':
            target = link.get('effect_evidence_id')
            if isinstance(target, str) and target in by_id:
                if target in native and native[target] != hook:
                    conflicting.add(target)
                native[target] = hook
    for target in conflicting:
        anchors.pop(target, None)
        native.pop(target, None)
        gap(f'Conflicting recorded tool links for {target}; tool attribution is not asserted.')

    def add(e):
        eid = e['metadata']['uid']
        nodes.setdefault(eid, {'id': eid, 'kind': kind(e), 'event': e,
                               'is_consequential': eid in triggers, 'on_path': False})
        return eid

    def connect(source, target, relation, basis, label):
        edges[source, target] = dict(source=source, target=target, relation=relation, basis=basis, label=label)

    def parent(e):
        eid = e['metadata']['uid']
        if eid in native:
            return native[eid], 'hook_resource_time_match', 'inferred', 'Tool attribution · resource and time'
        if eid in anchors:
            return anchors[eid], 'hook_command_time_match', 'inferred', 'Tool attribution · command and time'
        if kind(e) == 'hook':
            return None
        if kind(e) == 'process':
            key = meta(e).get('process_key')
            previous = [p for p in processes.get(key, []) if order(p) < order(e)] if key else []
            if previous:
                return previous[-1], 'process_exec', 'observed', 'Same process · execution transition'
            parent_key = meta(e).get('parent_process_key')
            if parent_key:
                p = active(parent_key, e)
                if p:
                    return p, 'process_parent', 'observed', 'Observed parent process'
                gap(f"Parent process evidence is missing for {eid}.")
            else:
                recorded = recorded_parents.get(eid, set())
                if len(recorded) == 1:
                    p = by_id.get(next(iter(recorded)))
                    parent_pid = (e.get('process', {}).get('parent_process') or {}).get('pid')
                    if p and kind(p) == 'process' and order(p) < order(e) and (not parent_pid or pid(p) == parent_pid):
                        return p, 'process_parent', 'observed', 'Recorded parent process'
                    gap(f'Recorded parent evidence is missing or inconsistent for {eid}.')
                elif len(recorded) > 1:
                    gap(f'Conflicting recorded parent evidence for {eid}.')
                elif (e.get('process', {}).get('parent_process') or {}).get('pid'):
                    gap(f"Parent lifetime identity is unavailable for {eid}; PID alone does not establish ancestry.")
            return None
        if kind(e) not in {'file_open', 'file_read', 'file_write', 'file_delete', 'network', 'network_send'}:
            return None
        p, basis = actor(e)
        if p:
            label = 'Observed process identity' if basis == 'observed' else 'Legacy PID match · unique retained lifetime'
            return p, 'process_emitted_effect', basis, label
        gap(f"Executing process could not be uniquely resolved for {eid}.")
        return None

    def walk(event, on_path):
        seen = set()
        for _ in range(256):
            eid = add(event)
            nodes[eid]['on_path'] |= on_path
            seen.add(eid)
            preceding = parent(event)
            if not preceding:
                return
            p, relation, basis, label = preceding
            source = p['metadata']['uid']
            if source in seen:
                gap(f"Cyclic process evidence was stopped at {eid}.")
                return
            add(p)
            connect(source, eid, relation, basis, label)
            event = p
        gap('Operation ancestry exceeded 256 steps; the retained partial chain is shown.')

    if not triggers:
        gap('This historical assessment does not identify its consequential events; no trigger is inferred.')
    missing = sorted((set(evidence_ids) | triggers) - by_id.keys())
    if missing:
        gap(f'{len(missing)} referenced evidence record(s) are unavailable.')
    for eid in sorted(triggers, key=lambda value: order(by_id[value]) if value in by_id else (0, 0, value)):
        if eid in by_id:
            walk(by_id[eid], True)
    main = set(nodes)
    # Related operations must belong to the assessed packet and connect to its path.
    # Context/state/hash/temporal associations are kept as supporting evidence.
    for eid in evidence_ids:
        e = by_id.get(eid)
        if not e or eid in nodes or kind(e) in {'hook', 'process', 'process_exit'}:
            continue
        old_nodes, old_edges, old_gaps = set(nodes), set(edges), list(gaps)
        walk(e, not triggers)
        added = set(nodes) - old_nodes
        connected = any(edge['source'] in main and edge['target'] in added for edge in edges.values())
        if triggers and not connected:
            for node_id in added:
                del nodes[node_id]
            for edge_id in set(edges) - old_edges:
                del edges[edge_id]
            gaps[:] = old_gaps
    if finding.get('tool_use_id') and not any(n['kind'] == 'hook' for n in nodes.values()):
        gap('The initiating tool call has no unique recorded link to this operation chain.')
    if uncertain:
        gap('Tool attribution is uncertain; no tool-to-process connection is asserted.')
    targets = {edge['target'] for edge in edges.values()}
    ordered = sorted(nodes.values(), key=lambda n: order(n['event']))
    return dict(finding_id=finding['finding_id'], revision=finding['revision'], nodes=ordered,
                edges=list(edges.values()), roots=[n['id'] for n in ordered if n['id'] not in targets],
                consequential_evidence_ids=sorted(triggers), gaps=gaps, associations=associations,
                missing_evidence_ids=missing,
                evidence=[by_id[eid] for eid in evidence_ids if eid in by_id])
