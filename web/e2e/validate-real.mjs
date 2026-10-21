// Compare real captures against JSONL, API projections and rendered UI.
// Usage: node e2e/validate-real.mjs /absolute/validation/report.json
import {chromium,expect} from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
const reportPath=process.argv[2];
const report=JSON.parse(fs.readFileSync(reportPath,'utf8'));
const base=process.env.TRACEWARD_DASHBOARD_URL||'http://127.0.0.1:8766';
const rows=p=>fs.readFileSync(p,'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);
const get=async p=>{const r=await fetch(base+p);if(!r.ok)throw Error(`API ${r.status} ${p}`);return r.json()};
const browser=await chromium.launch({channel:process.env.PLAYWRIGHT_CHANNEL||'chrome'});
const page=await browser.newPage({viewport:{width:1600,height:1100}});
let errors=[];page.on('pageerror',e=>errors.push(e.message));
await page.goto(base);
const screenshots=path.join(path.dirname(reportPath),'screenshots');fs.mkdirSync(screenshots,{mode:0o700,recursive:true});
for(const sample of report.cases){
 try{
  const id=sample.run_id;const folder=path.join(os.homedir(),'.local/state/traceward/runs',id);
  const events=rows(path.join(folder,'events.jsonl'));const byID=new Map(events.map(e=>[e.metadata.uid,e]));
  const revisions=rows(path.join(folder,'findings.jsonl'));const latest=new Map();for(const f of revisions)latest.set(f.finding_id,f);
  const api=await get(`/api/runs/${id}`);const summary=JSON.parse(fs.readFileSync(path.join(folder,'summary.json'),'utf8'));
  expect(api.summary).toEqual(summary);
  const pages=[];let cursor=null;do{const p=await get(`/api/runs/${id}/events?limit=500${cursor?'&before='+cursor:''}`);pages.unshift(p.events);cursor=p.next_before}while(cursor);
  const indexed=pages.flat();expect(indexed.length).toBe(events.length);expect(new Set(indexed.map(e=>e.metadata.uid)).size).toBe(events.length);
  expect(indexed.map(e=>e.time)).toEqual(indexed.map(e=>e.time).sort((a,b)=>a-b));
  for(const {index_id,...e} of indexed)expect(e).toEqual(byID.get(e.metadata.uid));
  const findings=(await get(`/api/runs/${id}/findings`)).findings;expect(findings.length).toBe(latest.size);
  for(const {revisions:history,...f} of findings){expect(f).toEqual(latest.get(f.finding_id));expect(history).toEqual(revisions.filter(r=>r.finding_id===f.finding_id))}
  await page.locator(`[data-run-id="${id}"]`).click();
  if(findings.length){
   const f=findings[0];await expect(page.locator('.finding-alert')).toHaveAttribute('data-status',f.status);
   await expect(page.locator('.finding-alert')).toHaveAttribute('data-revision',String(f.revision));
   await expect(page.locator('.finding-tabs button')).toHaveCount(findings.length);
   if(f.judge.status==='assessed'){
    await expect(page.locator('.structured-assessment')).toContainText(f.judge.disposition.replaceAll('_',' '));
    await expect(page.locator('.judge-rationale')).toHaveText(f.judge.rationale);
    await expect(page.locator('.structured-assessment')).toContainText('No numerical risk score');
    expect(f.uncalibrated_risk_score).toBeNull();
    await expect(page.locator('.judge-citations button')).toHaveCount(f.judge.cited_evidence_ids.length);
    await page.locator('.judge-citations button').first().click();
    await expect(page.locator('.detail-pair').filter({hasText:'Evidence ID'})).toContainText(f.judge.cited_evidence_ids[0]);
    await page.locator('.inspector .panel-head .close').click();
   }else await expect(page.locator('.score-top strong')).toContainText(String(Math.round(f.uncalibrated_risk_score*100)));
   await expect(page.locator('.section-label').filter({hasText:'DECISION MODEL'})).toContainText(f.judge.model);
   await page.getByText('Inspect exact evaluation packet and typed response').click();
   const audits=(await get(`/api/runs/${id}/evaluations`)).evaluations;
   expect(JSON.parse(await page.locator('.evaluation-json').innerText())).toEqual(audits.filter(e=>e.finding_id===f.finding_id));
   expect(audits).toEqual(rows(path.join(folder,'evaluations.jsonl')));
   await page.getByText('Inspect exact evaluation packet and typed response').click();
   const evidence=(await get(`/api/runs/${id}/evidence?ids=${encodeURIComponent(f.evidence_ids.join(','))}`)).events;
   expect(evidence.length).toBe(f.evidence_ids.length);
   for(const e of evidence){expect(e).toEqual(byID.get(e.metadata.uid));const ref=e.unmapped?.traceward?.raw_trace_ref;if(ref){const line=Number(ref.split(':').at(-1));const raw=await get(`/api/runs/${id}/raw?source=gvisor&line=${line}`);expect(raw.lines.some(r=>r.line===line)).toBe(true)}}
   for(const gap of new Set([...f.coverage_gaps,...summary.coverage_gaps]))await expect(page.locator('body')).toContainText(gap);
  }else{await expect(page.locator('.no-findings')).toContainText('No review findings')}
  await page.getByLabel('Event type').selectOption(findings.length?'evidence':'all');
  await page.getByRole('button',{name:'Timeline',exact:true}).click();
  await page.getByRole('button',{name:'Combined',exact:true}).click();
  await page.locator('.inspector-scroll').evaluateAll(items=>items.forEach(e=>e.scrollTop=0));
  await page.screenshot({path:path.join(screenshots,sample.case+'.png')});fs.chmodSync(path.join(screenshots,sample.case+'.png'),0o600);
  await page.getByRole('button',{name:'Hooks only',exact:true}).click();
  if(!findings.length){await page.getByLabel('Event type').selectOption('all');for(let i=0;i<12&&await page.locator('[data-kind="hook"]').count()===0;i++){const before=Number(await page.locator('.trace-panel').getAttribute('data-loaded-events'));await page.getByRole('button',{name:'Load earlier events'}).click();await expect.poll(async()=>Number(await page.locator('.trace-panel').getAttribute('data-loaded-events'))).toBeGreaterThan(before)}}
  await expect.poll(()=>page.locator('[data-kind="hook"]').count()).toBeGreaterThan(0);
  expect(await page.locator('[data-event-id]').evaluateAll(items=>items.every(e=>e.dataset.kind==='hook'))).toBe(true);
  await page.getByRole('button',{name:'Runtime only',exact:true}).click();await expect(page.locator('[data-kind="hook"]')).toHaveCount(0);
  await page.getByRole('button',{name:'Processes',exact:true}).click();
  const processes=(await get(`/api/runs/${id}/processes`)).processes;await expect(page.locator('.process-list button')).toHaveCount(processes.length);
  await page.getByRole('button',{name:'Hooks only',exact:true}).click();await expect(page.locator('.process-list button')).toHaveCount(0);
  await page.getByRole('button',{name:'Timeline',exact:true}).click();await page.getByRole('button',{name:'Combined',exact:true}).click();
  await page.getByLabel('Event type').selectOption('all');await page.getByRole('button',{name:'Load earlier events'}).click();
  const times=await page.locator('[data-time]').evaluateAll(items=>items.map(e=>Number(e.dataset.time)));expect(times).toEqual([...times].sort((a,b)=>a-b));
  const shown=await page.locator('[data-event-id]').evaluateAll(items=>items.map(e=>e.dataset.eventId));expect(new Set(shown).size).toBe(shown.length);
  if(findings.length){await page.getByLabel('Event type').selectOption('evidence');await page.locator('[data-kind="process"]').last().click();await page.getByRole('button',{name:'View raw trace excerpt'}).click();await expect(page.locator('.raw-modal')).toContainText('Raw gvisor excerpt');await page.locator('.raw-modal .close').click()}
  await page.reload();await page.locator(`[data-run-id="${id}"]`).click();if(findings.length)await expect(page.locator('.finding-alert')).toHaveAttribute('data-revision',String(findings[0].revision));else await expect(page.locator('.no-findings')).toBeVisible();
  sample.ui_passed=true;sample.ui_issues=[];
 }catch(e){sample.ui_passed=false;sample.ui_issues=[e.message.slice(0,500)];}
 console.log(JSON.stringify({case:sample.case,ui_passed:sample.ui_passed,issues:sample.ui_issues}));
 fs.writeFileSync(reportPath,JSON.stringify(report,null,2)+'\n',{mode:0o600});
}
report.browser_errors=errors;report.ui_passed=report.cases.every(r=>r.ui_passed)&&!errors.length;report.end_to_end_passed=report.passed&&report.ui_passed;
fs.writeFileSync(reportPath,JSON.stringify(report,null,2)+'\n',{mode:0o600});await browser.close();
process.exit(report.ui_passed?0:1);
