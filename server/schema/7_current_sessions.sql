-- Current interactive sessions for an identity.
CREATE INDEX IF NOT EXISTS current_sessions
ON jobs(job_id, interactive, time_started, time_ended)
WHERE time_started IS NOT NULL AND time_ended IS NULL;
