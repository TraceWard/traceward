import {useEffect, useState} from 'react';

type Bucket = {start: number; end: number; counts: Record<string, number>; total: number; finding_ids: string[]};
type Activity = {start: number | null; end: number | null; interval_seconds: number; total_events: number;
  buckets: Bucket[]; findings: {finding_id: string; title: string; start: number; end: number; source: string}[]};
const series = [
  ['process', 'Processes', '#5078be'], ['file_open', 'File opens', '#b7c9e3'],
  ['file_read', 'File reads', '#48a59b'], ['file_write', 'File writes', '#dda44b'], ['file_delete', 'File deletions', '#c36a6a'],
  ['network', 'Network', '#9380c8'], ['http_request', 'HTTP', '#4d9fbe'],
  ['hook', 'Agent hooks', '#7c8c9f'], ['other', 'State & context', '#d6dfe9'],
];
const clock = (value: number) => new Date(value).toLocaleTimeString([], {hour: '2-digit', minute: '2-digit', second: '2-digit'});
const duration = (seconds: number) => seconds < 60 ? `${seconds}s` : seconds < 3600 ? `${seconds/60}m` : seconds < 86400 ? `${seconds/3600}h` : `${seconds/86400}d`;

export default function ActivityChart({runId, live, onFinding}: {runId: string; live: boolean; onFinding: (id: string) => void}) {
  const [interval, setIntervalValue] = useState('auto');
  const [data, setData] = useState<Activity | null>(null);
  const [error, setError] = useState(false);
  const [retry, setRetry] = useState(0);
  const [hover, setHover] = useState<number | null>(null);
  const [selected, setSelected] = useState<number | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    let busy = false;
    const load = async () => {
      if (busy) return;
      busy = true;
      try {
        const response = await fetch(`/api/runs/${runId}/activity${interval === 'auto' ? '' : `?interval=${interval}`}`, {cache: 'no-store', signal: controller.signal});
        if (!response.ok) throw Error('Activity unavailable');
        const result = await response.json() as Activity;
        if (!controller.signal.aborted) { setData(result); setError(false); }
      } catch {
        if (!controller.signal.aborted) setError(true);
      } finally { busy = false; }
    };
    void load();
    const timer = window.setInterval(() => void load(), 2000);
    return () => { controller.abort(); window.clearInterval(timer); };
  }, [runId, interval, retry]);
  useEffect(() => {setHover(null); setSelected(null);}, [interval, data?.interval_seconds]);
  const bucket = data?.buckets.find(b => b.start === (hover ?? selected));
  const maximum = Math.max(1, ...(data?.buckets.map(b => b.total) || []));
  const scale = Math.pow(10, Math.floor(Math.log10(maximum/4 || 1)));
  const tick = Math.max(1, Math.ceil(maximum/4/scale)*scale);
  const top = tick*4;
  const related = bucket ? data?.findings.filter((f, i, all) => bucket.finding_ids.includes(f.finding_id) && all.findIndex(x => x.finding_id === f.finding_id) === i) || [] : [];
  const showDates = data?.start != null && data?.end != null && data.end-data.start >= 86400000;
  const stamp = (value: number) => showDates ? new Date(value).toLocaleString([], {month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'}) : clock(value);
  // Assessment periods are independent of the histogram's bucket boundaries.
  // Union overlapping/touching periods so one interval is one continuous band.
  const bands: {start: number; end: number; ids: Set<string>}[] = [];
  for (const finding of [...(data?.findings || [])].sort((a,b) => a.start-b.start)) {
    const start = Math.max(data?.start ?? finding.start, finding.start);
    const end = Math.min(data?.end ?? finding.end, finding.end);
    if (end < start) continue;
    const prior = bands[bands.length-1];
    if (prior && start <= prior.end) {prior.end = Math.max(prior.end, end); prior.ids.add(finding.finding_id);}
    else bands.push({start, end, ids: new Set([finding.finding_id])});
  }
  const quiet: {start: number; end: number}[] = [];
  let gapStart = -1;
  const buckets = data?.buckets || [];
  for (let i=0; i<=buckets.length; i++) {
    if (i < buckets.length && buckets[i].total === 0) {if (gapStart < 0) gapStart = i;}
    else if (gapStart >= 0) {
      if (i-gapStart >= Math.max(3, Math.ceil(buckets.length*.15))) quiet.push({start: buckets[gapStart].start, end: buckets[i-1].end});
      gapStart = -1;
    }
  }
  const position = (start: number, end: number) => ({left: `${(start-data!.start!)/(data!.end!-data!.start!)*100}%`, width: `${(end-start)/(data!.end!-data!.start!)*100}%`});
  const findingCount = new Set(data?.findings.map(f => f.finding_id)).size;
  return <section className="activity-card" aria-label="Activity over time">
    <div className="activity-heading">
      <div><h2>Activity over time</h2><p>{data ? `${data.total_events.toLocaleString()} activity events · ${duration(data.interval_seconds)} buckets` : 'Loading activity…'} <span className={`activity-live ${live ? 'is-live' : ''}`}>{live ? 'Live · updates every 2s' : 'Captured run'}</span></p></div>
      <label>Bucket duration <select aria-label="Activity bucket duration" value={interval} onChange={event => setIntervalValue(event.target.value)}>
        {[['auto','Auto'],['1','1 second'],['5','5 seconds'],['10','10 seconds'],['30','30 seconds'],['60','1 minute'],['300','5 minutes'],['3600','1 hour']].map(([value,label]) => <option key={value} value={value}>{label}</option>)}
      </select></label>
    </div>
    <div className="activity-legend" aria-label="Chart legend">
      {series.map(([key,label,color]) => <span key={key}><i style={{background: color}} />{label}</span>)}
      <span className="activity-finding-key"><i />Finding period{findingCount > 0 && ` · ${findingCount} ${findingCount === 1 ? 'finding' : 'findings'}`}</span>
    </div>
    {error ? <div className="activity-empty" role="status">Activity timeline unavailable. <button onClick={() => setRetry(retry+1)}>Retry timeline</button></div>
    : !data?.buckets.length ? <div className="activity-empty">{data ? 'No activity events captured yet.' : 'Loading timeline…'}</div>
    : <>
      <div className="activity-plot" onMouseLeave={() => setHover(null)}>
        <div className="activity-y" aria-hidden="true">{[4,3,2,1,0].map(value => <span key={value}>{(tick*value).toLocaleString()}</span>)}</div>
        <div className="activity-bars" aria-label="Stacked activity timeline">
          {bands.map(band => <div key={band.start} className="activity-finding-band" data-finding-count={band.ids.size}
            style={position(band.start, band.end)} aria-hidden="true" />)}
          {quiet.map(gap => <div key={gap.start} className="activity-quiet-period" style={position(gap.start, gap.end)} aria-hidden="true"><span>No recorded activity</span></div>)}
          {data.buckets.map(b => <button type="button" key={b.start} data-bucket-start={b.start} data-event-total={b.total}
            data-finding-count={b.finding_ids.length} className={`activity-bucket ${b.finding_ids.length ? 'has-finding' : ''} ${selected === b.start ? 'selected' : ''}`}
            aria-label={`${stamp(b.start)} to ${stamp(b.end)}: ${b.total} events${b.finding_ids.length ? `, overlaps ${b.finding_ids.length} finding periods` : ''}`}
            aria-pressed={selected === b.start}
            onMouseEnter={() => setHover(b.start)} onFocus={() => setHover(b.start)} onBlur={() => setHover(null)}
            onClick={() => {setSelected(selected === b.start ? null : b.start); setHover(null);}}>
            <span className="activity-stack" style={{height: `${b.total/top*100}%`}} aria-hidden="true">
              {series.map(([key,,color]) => b.counts[key] ? <span key={key} data-series={key} style={{height: `${b.counts[key]/b.total*100}%`, background: color}} /> : null)}
            </span>
          </button>)}
        </div>
      </div>
      <div className="activity-x" aria-hidden="true">{[0,.25,.5,.75,1].map(f => <span key={f}>{stamp(data.start!+(data.end!-data.start!)*f)}</span>)}</div>
      <div className="activity-detail" aria-live="polite">
        {bucket ? <>
          <strong>{stamp(bucket.start)} – {stamp(bucket.end)} <span>· {bucket.total.toLocaleString()} events</span></strong>
          <div className="activity-counts">{series.filter(([key]) => bucket.counts[key]).map(([key,label,color]) => <span key={key}><i style={{background: color}} />{label} <b>{bucket.counts[key].toLocaleString()}</b></span>)}{!bucket.total && <span>No events in this bucket</span>}</div>
          {related.length > 0 && <div className="activity-related">{related.map(f => <button type="button" key={f.finding_id} onClick={() => onFinding(f.finding_id)}><span>!</span>{f.title} <span aria-hidden="true">↗</span></button>)}</div>}
        </> : <p>Hover or select a time bucket for event counts. Select a highlighted bucket to inspect its findings.</p>}
      </div>
      <p className="activity-footnote">Continuous shading marks assessed periods associated with current findings; event bars are separate samples. Empty periods have no recorded activity events. Counts include HTTP request and response phases; TraceWard assessments are excluded.</p>
    </>}
  </section>;
}
