CREATE TABLE IF NOT EXISTS audit_events (
    id SERIAL PRIMARY KEY,
    trace_id VARCHAR(64) NOT NULL,
    event_type VARCHAR(128) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
