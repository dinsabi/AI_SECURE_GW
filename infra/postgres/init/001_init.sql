CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ DEFAULT NOW(),

    user_email TEXT,
    user_roles TEXT,
    department TEXT,
    country TEXT,

    original_prompt TEXT,
    masked_prompt TEXT,

    findings TEXT,
    sensitive BOOLEAN,

    risk_score INTEGER,
    risk_level TEXT,
    policy_action TEXT,
    policy_reason TEXT,

    model_type TEXT,
    status TEXT
);