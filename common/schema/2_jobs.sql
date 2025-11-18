CREATE TABLE IF NOT EXISTS jobs(
  job_id TEXT PRIMARY KEY NOT NULL,
  key_id TEXT REFERENCES certs,
  command TEXT,
  signature BLOB UNIQUE,
  time_reserved TEXT NOT NULL,
  time_started TEXT,
  time_ended TEXT,
  status INTEGER,
  stdout BLOB NOT NULL,
  stderr BLOB NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS jobs_reserved_only
ON jobs(job_id, time_reserved, time_started)
WHERE time_started IS NULL;
