"""Local, read-only investigation dashboard for TraceWard run files."""

import argparse
import asyncio
import ipaddress
import json
import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from .cli import state_root
from .records import assessment_record, effective_assessment
from .collector_status import describe_status


def _run_id(value: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except ValueError as exc:
        raise ValueError("invalid run ID") from exc
    if str(parsed) != value:
        raise ValueError("non-canonical run ID")
    return value


def _read_json(path: Path) -> dict | None:
    if path.is_symlink() or not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def _kind(event: dict) -> str:
    explicit = event.get("unmapped", {}).get("traceward", {}).get("event_kind")
    if explicit:
        return explicit
    uid = event.get("class_uid")
    activity = event.get("activity_id")
    traceward = event.get("unmapped", {}).get("traceward", {})
    if uid == 0:
        return "hook" if traceward.get("hook_event") else "coverage"
    if uid == 1001:
        return {14: "file_open", 2: "file_read", 3: "file_write", 4: "file_delete"}.get(activity, "file")
    if uid == 1007:
        return "process"
    if uid == 4001:
        return "network_send" if activity == 6 else "network"
    if uid == 2004:
        return "finding"
    return "other"


class RunIndex:
    """Rebuildable SQLite projection; JSONL remains the source of truth."""

    def __init__(self, runs_dir: Path, database: Path | None = None):
        self.runs_dir = runs_dir.expanduser().resolve()
        self.database = database or self.runs_dir.parent / "dashboard.sqlite"
        self.database.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.database.parent, 0o700)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.database, check_same_thread=False)
        os.chmod(self.database, 0o600)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS runs (
              run_id TEXT PRIMARY KEY, manifest TEXT, summary TEXT,
              updated_at REAL NOT NULL, ingest_errors INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS sources (
              run_id TEXT NOT NULL, name TEXT NOT NULL, inode INTEGER NOT NULL,
              offset INTEGER NOT NULL, PRIMARY KEY(run_id,name)
            );
            CREATE TABLE IF NOT EXISTS events (
              id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL,
              event_id TEXT NOT NULL, time_ms INTEGER, kind TEXT, source TEXT,
              pid INTEGER, body TEXT NOT NULL, UNIQUE(run_id,event_id)
            );
            CREATE INDEX IF NOT EXISTS events_run_order ON events(run_id,id);
            CREATE INDEX IF NOT EXISTS events_run_kind ON events(run_id,kind,id);
            CREATE INDEX IF NOT EXISTS events_run_time ON events(run_id,time_ms,id);
            CREATE TABLE IF NOT EXISTS findings (
              run_id TEXT NOT NULL, finding_id TEXT NOT NULL, revision INTEGER NOT NULL,
              time_s REAL, body TEXT NOT NULL,
              PRIMARY KEY(run_id,finding_id,revision)
            );
        """)
        self.db.commit()
        self.revision = 0

    def _run_dir(self, run_id: str) -> Path:
        path = self.runs_dir / _run_id(run_id)
        if path.is_symlink() or not path.is_dir():
            raise ValueError("run not found")
        return path

    def _ingest(self, run_id: str, path: Path, name: str) -> bool:
        if path.is_symlink() or not path.is_file():
            return False
        stat = path.stat()
        row = self.db.execute("SELECT inode,offset FROM sources WHERE run_id=? AND name=?",
                              (run_id, name)).fetchone()
        offset = int(row["offset"]) if row else 0
        changed = False
        if row and (row["inode"] != stat.st_ino or stat.st_size < offset):
            self.db.execute("DELETE FROM events WHERE run_id=?" if name == "events.jsonl"
                            else "DELETE FROM findings WHERE run_id=?", (run_id,))
            offset = 0
            changed = True
        if stat.st_size == offset:
            return changed
        with path.open("rb") as stream:
            stream.seek(offset)
            while True:
                line = stream.readline()
                if not line or not line.endswith(b"\n"):
                    break  # a concurrently written final line is retried next scan
                offset = stream.tell()
                try:
                    item = json.loads(line)
                    if not isinstance(item, dict):
                        raise ValueError("non-object record")
                    if name == "events.jsonl":
                        event_id = item["metadata"]["uid"]
                        extra = item.get("unmapped", {}).get("traceward", {})
                        pid = (item.get("process") or item.get("actor", {}).get("process") or {}).get("pid")
                        if pid is None:
                            pid = extra.get("pid")
                        self.db.execute("""INSERT OR IGNORE INTO events
                          (run_id,event_id,time_ms,kind,source,pid,body) VALUES (?,?,?,?,?,?,?)""",
                          (run_id, event_id, item.get("time"), _kind(item), extra.get("source"), pid,
                           json.dumps(item, separators=(",", ":"))))
                    else:
                        self.db.execute("""INSERT OR REPLACE INTO findings
                          (run_id,finding_id,revision,time_s,body) VALUES (?,?,?,?,?)""",
                          (run_id, item["finding_id"], int(item["revision"]), item.get("time"),
                           json.dumps(item, separators=(",", ":"))))
                except (KeyError, TypeError, ValueError, UnicodeDecodeError):
                    self.db.execute("UPDATE runs SET ingest_errors=ingest_errors+1 WHERE run_id=?",
                                    (run_id,))
                changed = True
        self.db.execute("""INSERT INTO sources(run_id,name,inode,offset) VALUES (?,?,?,?)
          ON CONFLICT(run_id,name) DO UPDATE SET inode=excluded.inode,offset=excluded.offset""",
          (run_id, name, stat.st_ino, offset))
        return changed

    def refresh(self) -> int:
        with self.lock:
            if not self.runs_dir.is_dir():
                return self.revision
            changed = False
            for path in self.runs_dir.iterdir():
                try:
                    run_id = _run_id(path.name)
                except ValueError:
                    continue
                if path.is_symlink() or not path.is_dir():
                    continue
                manifest = _read_json(path / "run.json")
                summary = _read_json(path / "summary.json")
                updated = max((p.stat().st_mtime for p in
                               (path / "run.json", path / "summary.json", path / "events.jsonl",
                                path / "findings.jsonl", path / 'assessments.jsonl') if p.is_file() and not p.is_symlink()),
                              default=path.stat().st_mtime)
                old = self.db.execute("SELECT manifest,summary,updated_at FROM runs WHERE run_id=?",
                                      (run_id,)).fetchone()
                manifest_text = json.dumps(manifest) if manifest else None
                summary_text = json.dumps(summary) if summary else None
                if not old or old["manifest"] != manifest_text or old["summary"] != summary_text or old["updated_at"] != updated:
                    self.db.execute("""INSERT INTO runs(run_id,manifest,summary,updated_at)
                      VALUES (?,?,?,?) ON CONFLICT(run_id) DO UPDATE SET manifest=excluded.manifest,
                      summary=excluded.summary,updated_at=excluded.updated_at""",
                      (run_id, manifest_text, summary_text, updated))
                    changed = True
                changed |= self._ingest(run_id, path / "events.jsonl", "events.jsonl")
                changed |= self._ingest(run_id, path / "findings.jsonl", "findings.jsonl")
                changed |= self._ingest(run_id, path / 'assessments.jsonl', 'assessments.jsonl')
            self.db.commit()
            if changed:
                self.revision += 1
            return self.revision

    def _public_run(self, row: sqlite3.Row) -> dict:
        manifest = json.loads(row["manifest"]) if row["manifest"] else {}
        summary = json.loads(row["summary"]) if row["summary"] else None
        heartbeat = manifest.get("heartbeat_at")
        status = "complete" if summary else "live" if isinstance(heartbeat, (int, float)) and time.time() - heartbeat < 10 else "incomplete"
        counts = self.db.execute("SELECT kind,COUNT(*) n FROM events WHERE run_id=? GROUP BY kind",
                                 (row["run_id"],)).fetchall()
        findings = self.db.execute("SELECT COUNT(DISTINCT finding_id) FROM findings WHERE run_id=?",
                                   (row["run_id"],)).fetchone()[0]
        latest_finding = self.db.execute("""SELECT body FROM findings WHERE run_id=?
          ORDER BY time_s DESC, revision DESC LIMIT 1""", (row["run_id"],)).fetchone()
        finding_title = (json.loads(latest_finding["body"]).get("title")
                         if latest_finding else None)
        assessments = self.assessments(row["run_id"])
        reviews = [f for f in assessments if f.get('status') == 'review_required']
        review_count = len(reviews)
        finding_title = reviews[0]['title'] if reviews else None
        cancelled = any(f['assessment_attempt_status'] == 'cancelled' for f in assessments)
        effective = [f.get('effective_judge') for f in assessments]
        if not assessments:
            evaluation_label = 'No consequential episode assessed'
        elif any(j and ('demo' in j.get('model', '') or j.get('evaluation_source') == 'simulated') for j in effective):
            evaluation_label = 'Simulated evaluator · not a model assessment'
        elif cancelled:
            evaluation_label = 'Assessed · final review cancelled' if any(effective) else 'Assessment cancelled'
        elif summary and summary.get('assessment_mode') == 'realtime' and summary.get('pending_assessment_count'):
            evaluation_label = 'Assessed · additional evidence pending' if any(effective) else 'Assessment pending · session ended'
        elif all(f['assessment_attempt_status'] == 'assessed' for f in assessments):
            evaluation_label = 'Model assessed'
        elif any(f.get('retained_review_revision') and f.get('effective_judge') for f in assessments):
            evaluation_label = 'Earlier assessment retained · latest assessment unavailable'
        elif any(f['assessment_attempt_status'] == 'unavailable' for f in assessments):
            evaluation_label = 'Partly assessed · some assessments unavailable' if any(effective) else 'Model unavailable'
        else:
            evaluation_label = 'Partly assessed · assessments pending' if any(effective) else 'Assessment pending'
        observed = self.db.execute("SELECT COUNT(*) FROM events WHERE run_id=? AND source='gvisor' AND kind!='coverage'", (row['run_id'],)).fetchone()[0]
        telemetry = (summary or {}).get('telemetry_status') or describe_status(summary or {}, observed)
        if summary and telemetry['trace_established'] and not telemetry['finalized']:
            original_gaps = summary.get('coverage_gaps', [])
            misleading = 'gVisor telemetry was not established; run coverage is incomplete'
            if misleading in original_gaps:
                summary = {**summary, 'source_coverage_gaps': original_gaps,
                    'coverage_gaps': [telemetry['message'] if gap == misleading else gap for gap in original_gaps]}
        analysis_incomplete = bool(summary and (summary.get('final_review_complete') is False
            or summary.get('assessment_wait_cancelled') or any(f['assessment_attempt_status'] in {'cancelled', 'unavailable', 'pending'} for f in assessments)))
        return {"run_id": row["run_id"], "name": manifest.get("name") or manifest.get("run_name"),
                "goal": manifest.get("goal") or (summary or {}).get("goal") or "Goal unavailable",
                "started_at": manifest.get("started_at") or row["updated_at"], "updated_at": row["updated_at"],
                "status": status, "summary": summary, "telemetry_status": telemetry, "analysis_incomplete": analysis_incomplete, "event_counts": {r["kind"]: r["n"] for r in counts},
                "finding_count": review_count, "assessment_count": len(assessments), "finding_title": finding_title,
                "review_count": review_count, "evaluation_label": evaluation_label,
                "source": manifest.get("source", "unknown"), "demo_case": manifest.get("demo_case"),
                "legacy": manifest.get("observer_version") not in {"assessment-v2", "gvisor-v1"},
                "ingest_errors": row["ingest_errors"]}

    def runs(self) -> list[dict]:
        with self.lock:
            rows = self.db.execute("SELECT * FROM runs ORDER BY updated_at DESC").fetchall()
            return [self._public_run(row) for row in rows]

    def run(self, run_id: str) -> dict | None:
        with self.lock:
            row = self.db.execute("SELECT * FROM runs WHERE run_id=?", (_run_id(run_id),)).fetchone()
            return self._public_run(row) if row else None

    def events(self, run_id: str, *, before: int | None = None, limit: int = 250,
               kind: str | None = None, source: str | None = None, pid: int | None = None,
               hook_event: str | None = None) -> dict:
        with self.lock:
            query = "SELECT id,body FROM events WHERE run_id=?"
            values: list = [_run_id(run_id)]
            if before is not None:
                cursor = self.db.execute("SELECT COALESCE(time_ms,0) time_ms,id FROM events WHERE run_id=? AND id=?",
                                         (run_id, before)).fetchone()
                if not cursor:
                    return {"events": [], "next_before": None}
                query += " AND (COALESCE(time_ms,0),id)<(?,?)"
                values.extend([cursor["time_ms"], cursor["id"]])
            for clause, value in (("kind=?", kind), ("source=?", source), ("pid=?", pid)):
                if value is not None:
                    query += " AND " + clause
                    values.append(value)
            if hook_event is not None:
                query += " AND kind='hook' AND json_extract(body,'$.unmapped.traceward.hook_event')=?"
                values.append(hook_event)
            query += " ORDER BY COALESCE(time_ms,0) DESC,id DESC LIMIT ?"
            page_size = min(max(limit, 1), 500)
            values.append(page_size + 1)
            rows = self.db.execute(query, values).fetchall()
            has_more = len(rows) > page_size
            rows = rows[:page_size]
            result = {"events": [{"index_id": row["id"], **json.loads(row["body"])} for row in reversed(rows)],
                      "next_before": rows[-1]["id"] if rows and has_more else None}
            if kind == 'hook' or hook_event is not None:
                result['hook_events'] = [row[0] for row in self.db.execute(
                    "SELECT DISTINCT json_extract(body,'$.unmapped.traceward.hook_event') name "
                    "FROM events WHERE run_id=? AND kind='hook' ORDER BY name", (run_id,)) if row[0]]
            return result

    def assessments(self, run_id: str) -> list[dict]:
        with self.lock:
            rows = self.db.execute("""SELECT f.body FROM findings f JOIN
              (SELECT finding_id,MAX(revision) revision FROM findings WHERE run_id=? GROUP BY finding_id) latest
              ON f.finding_id=latest.finding_id AND f.revision=latest.revision
              WHERE f.run_id=? ORDER BY f.time_s DESC""", (_run_id(run_id), run_id)).fetchall()
            results = []
            for row in rows:
                finding = assessment_record(json.loads(row["body"]))
                revisions = self.db.execute("""SELECT body FROM findings WHERE run_id=? AND finding_id=?
                  ORDER BY revision""", (run_id, finding["finding_id"])).fetchall()
                finding["revisions"] = [assessment_record(json.loads(rev["body"])) for rev in revisions]
                results.append(effective_assessment(finding, finding["revisions"]))
            return results

    def findings(self, run_id: str) -> list[dict]:
        return [f for f in self.assessments(run_id) if f.get('status') == 'review_required']

    def activity(self, run_id: str, interval_seconds: int | None = None) -> dict:
        from .activity import histogram
        with self.lock:
            row = self.db.execute('SELECT manifest,summary FROM runs WHERE run_id=?', (_run_id(run_id),)).fetchone()
            manifest = json.loads(row['manifest']) if row and row['manifest'] else {}
            summary = json.loads(row['summary']) if row and row['summary'] else None
            return histogram(self.db, run_id, manifest, summary, self.findings(run_id), interval_seconds)

    def all_findings(self) -> list[dict]:
        """Latest review findings across runs, excluding withdrawals and audit records."""
        with self.lock:
            rows = self.db.execute("""SELECT f.run_id,f.body FROM findings f JOIN
              (SELECT run_id,finding_id,MAX(revision) revision FROM findings
               GROUP BY run_id,finding_id) latest
              ON f.run_id=latest.run_id AND f.finding_id=latest.finding_id
                 AND f.revision=latest.revision
              ORDER BY f.time_s DESC,f.run_id,f.finding_id""").fetchall()
            results = []
            for row in rows:
                finding = json.loads(row['body'])
                if finding.get('status') == 'review_required':
                    results.append({**finding, 'run_id': row['run_id']})
            return results

    def processes(self, run_id: str) -> list[dict]:
        with self.lock:
            rows = self.db.execute("""SELECT body FROM events WHERE run_id=? AND kind='process'
              ORDER BY time_ms,id LIMIT 5000""", (_run_id(run_id),)).fetchall()
            return [json.loads(row["body"]) for row in rows]

    def evidence(self, run_id: str, event_ids: list[str]) -> list[dict]:
        if not event_ids:
            return []
        with self.lock:
            ids = event_ids[:100]
            markers = ",".join("?" for _ in ids)
            rows = self.db.execute(f"SELECT body FROM events WHERE run_id=? AND event_id IN ({markers}) ORDER BY time_ms,id",
                                   [_run_id(run_id), *ids]).fetchall()
            return [json.loads(row["body"]) for row in rows]

    def operation_chain(self, run_id: str, finding_id: str, revision: int | None = None) -> dict | None:
        from .operation_chain import build_operation_chain
        with self.lock:
            row = self.db.execute(
                'SELECT body FROM findings WHERE run_id=? AND finding_id=? '
                + ('AND revision=? ' if revision is not None else '')
                + 'ORDER BY revision DESC LIMIT 1',
                (run_id, finding_id, revision) if revision is not None else (run_id, finding_id)).fetchone()
            if row is None:
                return None
            finding = json.loads(row['body'])
            # Fetch lifecycle anchors across the run, not a paginated timeline.
            rows = list(self.db.execute(
                "SELECT id,body FROM events WHERE run_id=? AND kind IN ('process','process_exit','hook')",
                (run_id,)))
            ids = list(set(finding.get('evidence_ids', [])) | set(finding.get('consequential_evidence_ids', [])))
            for start in range(0, len(ids), 500):
                chunk = ids[start:start + 500]
                markers = ','.join('?' for _ in chunk)
                rows.extend(self.db.execute(
                    f'SELECT id,body FROM events WHERE run_id=? AND event_id IN ({markers})', (run_id, *chunk)))
            events = {row['id']: {**json.loads(row['body']), 'index_id': row['id']} for row in rows}
            return {**build_operation_chain(finding, list(events.values())), 'run_id': run_id,
                    'projection_revision': self.revision}

    def evaluations(self, run_id: str) -> list[dict]:
        path = self._run_dir(run_id) / "evaluations.jsonl"
        if path.is_symlink() or not path.is_file():
            return []
        result = []
        with path.open(encoding="utf-8") as stream:
            for line in stream:
                if not line.endswith("\n"):
                    break
                try:
                    item = json.loads(line)
                except ValueError:
                    continue
                if isinstance(item, dict):
                    result.append(item)
                if len(result) >= 500:
                    break
        return result

    def raw_excerpt(self, run_id: str, source: str, line: int, context: int = 8) -> dict:
        if source not in {"gvisor", "strace", "hooks"} or line < 1:
            raise ValueError("invalid raw source or line")
        path = self._run_dir(run_id) / {"gvisor": "raw.gvisor.jsonl", "strace": "raw.strace", "hooks": "hooks.jsonl"}[source]
        if path.is_symlink() or not path.is_file():
            raise ValueError("raw source unavailable")
        context = min(max(context, 0), 40)
        start, end = max(1, line - context), line + context
        excerpt = []
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            for number, content in enumerate(stream, 1):
                if number > end:
                    break
                if number >= start:
                    excerpt.append({"line": number, "text": content.rstrip("\n")[:2000]})
        return {"source": source, "lines": excerpt, "truncated": len(excerpt) >= 81}


def create_app(index: RunIndex, assets: Path | None = None, *, bind_host: str = "0.0.0.0"):
    try:
        from fastapi import FastAPI, HTTPException, Query, Request
        from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
        from fastapi.staticfiles import StaticFiles
    except ImportError as exc:
        raise RuntimeError("dashboard dependencies missing; install with pip install -e '.[dashboard]'") from exc

    app = FastAPI(title="TraceWard local dashboard", docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def same_origin_only(request: Request, call_next):
        # Accept IP literals for LAN access without trusting arbitrary DNS names.
        try:
            host = request.url.hostname or ""
            if host not in {"localhost", bind_host.lower()}:
                ipaddress.ip_address(host)
        except ValueError:
            return JSONResponse({"detail": "IP address or configured host required"}, status_code=403)
        origin = request.headers.get("origin")
        if origin:
            try:
                parsed = urlsplit(origin)
                default_ports = {"http": 80, "https": 443}
                same_origin = (parsed.scheme, parsed.hostname, parsed.port or default_ports.get(parsed.scheme)) == (
                    request.url.scheme, host, request.url.port or default_ports.get(request.url.scheme))
            except ValueError:
                same_origin = False
            if not same_origin:
                return JSONResponse({"detail": "cross-origin requests disabled"}, status_code=403)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'"
        return response

    def required_run(run_id: str) -> dict:
        try:
            run = index.run(run_id)
        except ValueError:
            run = None
        if run is None:
            raise HTTPException(404, "run not found")
        return run

    @app.get("/api/health")
    def health():
        return {"status": "ok", "runs_dir": str(index.runs_dir)}

    @app.get("/api/runs")
    def runs():
        index.refresh()
        return {"runs": index.runs(), "revision": index.revision}

    @app.get("/api/findings")
    def all_findings():
        index.refresh()
        return {"findings": index.all_findings(), "revision": index.revision}

    @app.get("/api/runs/{run_id}")
    def run(run_id: str):
        index.refresh()
        return required_run(run_id)

    @app.get("/api/runs/{run_id}/events")
    def events(run_id: str, before: int | None = None, limit: int = 250,
               kind: str | None = None, source: str | None = None, pid: int | None = None,
               hook_event: str | None = None):
        index.refresh()
        required_run(run_id)
        return index.events(run_id, before=before, limit=limit, kind=kind, source=source, pid=pid, hook_event=hook_event)

    @app.get("/api/runs/{run_id}/findings")
    def findings(run_id: str):
        index.refresh()
        required_run(run_id)
        return {"findings": index.findings(run_id)}

    @app.get('/api/runs/{run_id}/activity')
    def activity(run_id: str, interval: int | None = Query(default=None, ge=1, le=86400)):
        index.refresh()
        required_run(run_id)
        return index.activity(run_id, interval)

    @app.get('/api/runs/{run_id}/findings/{finding_id}/operation-chain')
    def operation_chain(run_id: str, finding_id: str, revision: int | None = Query(default=None, ge=1)):
        index.refresh()
        required_run(run_id)
        result = index.operation_chain(run_id, finding_id, revision)
        if result is None:
            raise HTTPException(404, 'Assessment revision not found')
        return result

    @app.get("/api/runs/{run_id}/processes")
    def processes(run_id: str):
        index.refresh()
        required_run(run_id)
        return {"processes": index.processes(run_id)}

    @app.get('/api/runs/{run_id}/assessments')
    def assessments(run_id: str):
        index.refresh()
        required_run(run_id)
        return {'assessments': index.assessments(run_id)}

    @app.get("/api/runs/{run_id}/evaluations")
    def evaluations(run_id: str):
        index.refresh()
        required_run(run_id)
        return {"evaluations": index.evaluations(run_id)}

    @app.get("/api/runs/{run_id}/evidence")
    def evidence(run_id: str, ids: str = ""):
        index.refresh()
        required_run(run_id)
        return {"events": index.evidence(run_id, [value for value in ids.split(",") if value])}

    @app.get("/api/runs/{run_id}/raw")
    def raw(run_id: str, source: str, line: int,
            context: int = Query(default=8, ge=0, le=40)):
        index.refresh()
        required_run(run_id)
        try:
            return index.raw_excerpt(run_id, source, line, context)
        except ValueError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.get("/api/stream")
    async def stream(request: Request):
        async def updates():
            last = -1
            while not await request.is_disconnected():
                current = await asyncio.to_thread(index.refresh)
                if current != last:
                    yield f"data: {json.dumps({'revision': current})}\n\n"
                    last = current
                else:
                    yield ": keepalive\n\n"
                await asyncio.sleep(0.75)
        return StreamingResponse(updates(), media_type="text/event-stream")

    if assets and (assets / "index.html").is_file():
        app.mount("/assets", StaticFiles(directory=assets / "assets"), name="assets")

        @app.get("/")
        def home():
            return FileResponse(assets / "index.html")

    return app


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="traceward dashboard")
    parser.add_argument("--runs-dir", type=Path, default=state_root())
    parser.add_argument("--host", default="0.0.0.0", help="bind address (default: 0.0.0.0, all IPv4 interfaces)")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    assets = Path(__file__).parent / "dashboard_assets"
    if not (assets / "index.html").is_file():
        raise RuntimeError("dashboard assets missing; run 'npm ci && npm run build' in web/")
    import uvicorn
    index = RunIndex(args.runs_dir)
    display_host = f"[{args.host}]" if ":" in args.host else args.host
    print(f"TraceWard dashboard: http://{display_host}:{args.port} (reading {index.runs_dir})", flush=True)
    if args.host == "0.0.0.0":
        print(f"Open http://localhost:{args.port} locally, or http://<this computer's LAN IP>:{args.port} on your network.", flush=True)
    uvicorn.run(create_app(index, assets, bind_host=args.host), host=args.host, port=args.port, access_log=False)
    return 0
