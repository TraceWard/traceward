ALTER TABLE evaluations ADD COLUMN revision integer NOT NULL DEFAULT 0;
UPDATE evaluations SET revision=COALESCE((body->>'revision')::integer,0);
ALTER TABLE evaluations DROP CONSTRAINT evaluations_pkey;
ALTER TABLE evaluations ADD PRIMARY KEY(run_id,signature,revision);
