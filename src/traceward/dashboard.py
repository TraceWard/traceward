"""Local, read-only investigation dashboard for TraceWard run files."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from .cli import state_root


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
    uid = event.get("class_uid")
    activity = event.get("activity_id")
    traceward = event.get("unmapped", {}).get("traceward", {})
    if uid == 0:
        return "hook" if traceward.get("hook_event") else "coverage"
    if uid == 1001:
        return {14: "file_open", 2: "file_read", 3: "file_write"}.get(activity, "file")
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
                                path / "findings.jsonl") if p.is_file() and not p.is_symlink()),
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
        return {"run_id": row["run_id"], "goal": manifest.get("goal") or (summary or {}).get("goal") or "Goal unavailable",
                "started_at": manifest.get("started_at") or row["updated_at"], "updated_at": row["updated_at"],
                "status": status, "summary": summary, "event_counts": {r["kind"]: r["n"] for r in counts},
                "finding_count": findings, "finding_title": finding_title,
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
               kind: str | None = None, source: str | None = None, pid: int | None = None) -> dict:
        with self.lock:
            query = "SELECT id,body FROM events WHERE run_id=?"
            values: list = [_run_id(run_id)]
            for clause, value in (("id<?", before), ("kind=?", kind), ("source=?", source), ("pid=?", pid)):
                if value is not None:
                    query += " AND " + clause
                    values.append(value)
            query += " ORDER BY id DESC LIMIT ?"
            values.append(min(max(limit, 1), 500))
            rows = self.db.execute(query, values).fetchall()
            return {"events": [{"index_id": row["id"], **json.loads(row["body"])} for row in reversed(rows)],
                    "next_before": rows[-1]["id"] if rows else None}

    def findings(self, run_id: str) -> list[dict]:
        with self.lock:
            rows = self.db.execute("""SELECT f.body FROM findings f JOIN
              (SELECT finding_id,MAX(revision) revision FROM findings WHERE run_id=? GROUP BY finding_id) latest
              ON f.finding_id=latest.finding_id AND f.revision=latest.revision
              WHERE f.run_id=? ORDER BY f.time_s DESC""", (_run_id(run_id), run_id)).fetchall()
            results = []
            for row in rows:
                finding = json.loads(row["body"])
                revisions = self.db.execute("""SELECT body FROM findings WHERE run_id=? AND finding_id=?
                  ORDER BY revision""", (run_id, finding["finding_id"])).fetchall()
                finding["revisions"] = [json.loads(rev["body"]) for rev in revisions]
                results.append(finding)
            return results

    def processes(self, run_id: str) -> list[dict]:
        with self.lock:
            rows = self.db.execute("""SELECT body FROM events WHERE run_id=? AND kind='process'
              ORDER BY id LIMIT 5000""", (_run_id(run_id),)).fetchall()
            return [json.loads(row["body"]) for row in rows]

    def evidence(self, run_id: str, event_ids: list[str]) -> list[dict]:
        if not event_ids:
            return []
        with self.lock:
            ids = event_ids[:100]
            markers = ",".join("?" for _ in ids)
            rows = self.db.execute(f"SELECT body FROM events WHERE run_id=? AND event_id IN ({markers})",
                                   [_run_id(run_id), *ids]).fetchall()
            found = {item["metadata"]["uid"]: item for item in (json.loads(row["body"]) for row in rows)}
            return [found[event_id] for event_id in ids if event_id in found]

    def raw_excerpt(self, run_id: str, source: str, line: int, context: int = 8) -> dict:
        if source not in {"strace", "hooks"} or line < 1:
            raise ValueError("invalid raw source or line")
        path = self._run_dir(run_id) / ("raw.strace" if source == "strace" else "hooks.jsonl")
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


def create_app(index: RunIndex, assets: Path | None = None):
    try:
        from fastapi import FastAPI, HTTPException, Query, Request
        from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
        from fastapi.staticfiles import StaticFiles
    except ImportError as exc:
        raise RuntimeError("dashboard dependencies missing; install with pip install -e '.[dashboard]'") from exc

    app = FastAPI(title="TraceWard local dashboard", docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def local_only(request: Request, call_next):
        host = request.headers.get("host", "").split(":")[0].lower()
        origin = request.headers.get("origin")
        if host not in {"127.0.0.1", "localhost"}:
            return JSONResponse({"detail": "local host only"}, status_code=403)
        if origin:
            parsed = urlsplit(origin)
            if parsed.hostname not in {"127.0.0.1", "localhost"} or parsed.port != request.url.port:
                return JSONResponse({"detail": "cross-origin requests disabled"}, status_code=403)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'"
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

    @app.get("/api/runs/{run_id}")
    def run(run_id: str):
        index.refresh()
        return required_run(run_id)

    @app.get("/api/runs/{run_id}/events")
    def events(run_id: str, before: int | None = None, limit: int = 250,
               kind: str | None = None, source: str | None = None, pid: int | None = None):
        index.refresh()
        required_run(run_id)
        return index.events(run_id, before=before, limit=limit, kind=kind, source=source, pid=pid)

    @app.get("/api/runs/{run_id}/findings")
    def findings(run_id: str):
        index.refresh()
        required_run(run_id)
        return {"findings": index.findings(run_id)}

    @app.get("/api/runs/{run_id}/processes")
    def processes(run_id: str):
        index.refresh()
        required_run(run_id)
        return {"processes": index.processes(run_id)}

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
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    assets = Path(__file__).parent / "dashboard_assets"
    if not (assets / "index.html").is_file():
        raise RuntimeError("dashboard assets missing; run 'npm ci && npm run build' in web/")
    import uvicorn
    index = RunIndex(args.runs_dir)
    print(f"TraceWard dashboard: http://127.0.0.1:{args.port} (reading {index.runs_dir})", flush=True)
    uvicorn.run(create_app(index, assets), host="127.0.0.1", port=args.port, access_log=False)
    return 0
