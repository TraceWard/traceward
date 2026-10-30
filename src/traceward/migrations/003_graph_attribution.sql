UPDATE graph_observations g
SET payload=g.payload || jsonb_build_object('agent_id',r.agent_id,'agent_slug',r.agent_slug)
FROM runs r WHERE g.run_id=r.run_id;
