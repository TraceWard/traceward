"""Bounded activity histograms over the complete dashboard read model."""
import math
import time

SERIES = {
    'process': 'Processes', 'file_open': 'File opens', 'file_read': 'File reads',
    'file_write': 'File writes', 'file_delete': 'File deletions', 'network': 'Network', 'http_request': 'HTTP',
    'hook': 'Tools', 'other': 'State & context',
}
EXCLUDED = ('assessment', 'finding', 'coverage')
STEPS = (1, 5, 10, 30, 60, 300, 900, 1800, 3600, 10800, 21600, 43200, 86400, 604800)


def histogram(db, run_id, manifest, summary, findings, interval_seconds=None):
    marks = ','.join('?' for _ in EXCLUDED)
    where = f'run_id=? AND kind NOT IN ({marks}) AND time_ms IS NOT NULL'
    params = [run_id, *EXCLUDED]
    bounds = db.execute(f'SELECT MIN(time_ms),MAX(time_ms) FROM events WHERE {where}', params).fetchone()
    if bounds[0] is None:
        return {'buckets': [], 'findings': [], 'series': SERIES, 'interval_seconds': interval_seconds or 1,
                'total_events': 0, 'start': None, 'end': None}
    start, end = bounds[0], bounds[1]
    # Historical/synthetic source clocks can differ from the manifest clock.
    # Only extend a live chart when they share the launch's clock domain.
    launch = manifest.get('started_at', 0)*1000
    heartbeat = manifest.get('heartbeat_at', 0)
    if not summary and time.time()-heartbeat < 10 and start >= launch-60000:
        end = max(end, int(time.time()*1000))
    span = end-start
    minimum = max(interval_seconds or 1, math.ceil(span/100000) if interval_seconds is None else math.ceil(span/238000))
    step = next((s for s in STEPS if s >= minimum), math.ceil(minimum/604800)*604800)
    width = step*1000
    first, last = start//width*width, end//width*width
    buckets = {t: {'start': t, 'end': t+width, 'counts': {}, 'total': 0, 'finding_ids': []}
               for t in range(first, last+1, width)}
    rows = db.execute(f'SELECT CAST(time_ms/? AS INTEGER)*? bucket,kind,COUNT(*) n FROM events '
                      f'WHERE {where} GROUP BY bucket,kind', [width, width, *params]).fetchall()
    for row in rows:
        category = {'process_exit': 'process', 'network_send': 'network'}.get(row['kind'], row['kind'])
        if category not in SERIES: category = 'other'
        bucket = buckets[row['bucket']]
        bucket['counts'][category] = bucket['counts'].get(category, 0)+row['n']
        bucket['total'] += row['n']
    windows = []
    for finding in findings:
        seen = set()
        reviews = [f for f in finding.get('revisions', []) if f.get('status') == 'review_required'] or [finding]
        for review in reviews:
            window = review.get('analysis_window') or {}
            begin, finish = window.get('start'), window.get('end')
            source = 'assessment_window'
            if not (isinstance(begin, (int, float)) and isinstance(finish, (int, float))
                    and math.isfinite(begin) and math.isfinite(finish) and 0 <= begin <= finish):
                ids = review.get('consequential_evidence_ids') or review.get('evidence_ids', [])
                if ids:
                    placeholders = ','.join('?' for _ in ids)
                    times = db.execute(f'SELECT MIN(time_ms),MAX(time_ms) FROM events WHERE run_id=? AND event_id IN ({placeholders})',
                                       [run_id, *ids]).fetchone()
                else: times = (None, None)
                begin = (times[0]/1000) if times[0] is not None else review.get('time')
                finish = (times[1]/1000) if times[1] is not None else begin
                source = 'evidence_time' if times[0] is not None else 'detection_time'
            if not isinstance(begin, (int, float)) or not isinstance(finish, (int, float)) or not math.isfinite(begin) or not math.isfinite(finish): continue
            begin, finish = int(begin*1000), int(finish*1000)
            if (begin, finish) in seen: continue
            seen.add((begin, finish))
            windows.append({'finding_id': finding['finding_id'], 'title': finding['title'],
                            'start': begin, 'end': finish, 'source': source})
            for bucket in buckets.values():
                if begin < bucket['end'] and finish >= bucket['start'] and finding['finding_id'] not in bucket['finding_ids']:
                    bucket['finding_ids'].append(finding['finding_id'])
    return {'start': first, 'end': last+width, 'interval_seconds': step, 'series': SERIES,
            'buckets': list(buckets.values()), 'findings': windows,
            'total_events': sum(b['total'] for b in buckets.values())}
