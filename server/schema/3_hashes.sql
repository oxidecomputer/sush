-- WARNING: Destructive!
ALTER TABLE jobs DROP COLUMN stdout;
ALTER TABLE jobs DROP COLUMN stderr;
ALTER TABLE jobs ADD COLUMN stdout_hash TEXT CHECK (length(stdout_hash) = 64);
ALTER TABLE jobs ADD COLUMN stderr_hash TEXT CHECK (length(stderr_hash) = 64);
