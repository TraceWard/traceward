CREATE TABLE IF NOT EXISTS agents (
 agent_id text PRIMARY KEY, agent_slug text UNIQUE NOT NULL,
 goal text NOT NULL, created_at double precision NOT NULL);
CREATE TABLE IF NOT EXISTS runs (
 run_id text PRIMARY KEY, agent_id text REFERENCES agents(agent_id), agent_slug text,
 goal text, manifest jsonb NOT NULL, summary jsonb, metadata jsonb NOT NULL DEFAULT '{}',
 updated_at double precision NOT NULL, heartbeat_at double precision NOT NULL,
 capture_state text NOT NULL DEFAULT 'registered', analysis_state text NOT NULL DEFAULT 'pending',
 ingest_errors integer NOT NULL DEFAULT 0, accepted_seq bigint NOT NULL DEFAULT 0,
 processed_seq bigint NOT NULL DEFAULT 0, final_seq bigint, capture_result jsonb,
 analysis_error text);
CREATE INDEX IF NOT EXISTS runs_agent ON runs(agent_id,updated_at DESC);
CREATE TABLE IF NOT EXISTS inputs (
 run_id text REFERENCES runs(run_id), seq bigint, digest text NOT NULL, body jsonb NOT NULL,
 PRIMARY KEY(run_id,seq));
CREATE TABLE IF NOT EXISTS raw_sources (
 run_id text REFERENCES runs(run_id), source text, line_no bigint, data bytea NOT NULL,
 PRIMARY KEY(run_id,source,line_no));
CREATE TABLE IF NOT EXISTS events (
 id bigserial PRIMARY KEY, run_id text REFERENCES runs(run_id), event_id text NOT NULL,
 time_ms bigint, kind text, source text, pid bigint, body jsonb NOT NULL,
 UNIQUE(run_id,event_id));
CREATE INDEX IF NOT EXISTS events_run_time ON events(run_id,time_ms,id);
CREATE INDEX IF NOT EXISTS events_run_kind ON events(run_id,kind,id);
CREATE TABLE IF NOT EXISTS findings (
 run_id text REFERENCES runs(run_id), finding_id text, revision integer,
 time_s double precision, body jsonb NOT NULL, PRIMARY KEY(run_id,finding_id,revision));
CREATE TABLE IF NOT EXISTS evaluations (
 run_id text REFERENCES runs(run_id), signature text, body jsonb NOT NULL,
 request_bytes bytea, PRIMARY KEY(run_id,signature));
CREATE TABLE IF NOT EXISTS graph_observations (
 id text PRIMARY KEY, run_id text, time double precision, kind text, path text,
 version text, content_hash text, phase text, tool_id text, payload jsonb NOT NULL);
CREATE INDEX IF NOT EXISTS graph_run_time ON graph_observations(run_id,time);
CREATE INDEX IF NOT EXISTS graph_version ON graph_observations(version);
CREATE TABLE IF NOT EXISTS graph_edges (
 source text, target text, relation text, confidence text,
 PRIMARY KEY(source,target,relation));
CREATE TABLE IF NOT EXISTS changes(id integer PRIMARY KEY, revision bigint NOT NULL);
INSERT INTO changes VALUES(1,0) ON CONFLICT DO NOTHING;
