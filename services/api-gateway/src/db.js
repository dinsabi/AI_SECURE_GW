import pg from "pg";

const { Pool } = pg;

export const pool = new Pool({
  host: process.env.PGHOST || "postgres",
  port: Number(process.env.PGPORT || 5432),
  database: process.env.PGDATABASE || "aigw",
  user: process.env.PGUSER || "aigw",
  password: process.env.PGPASSWORD || "aigwpass",
});

export async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS audit_events (
      id SERIAL PRIMARY KEY,
      event_type TEXT NOT NULL,
      route TEXT,
      user_email TEXT,
      department TEXT,
      roles TEXT,
      country TEXT,
      mfa_verified BOOLEAN DEFAULT FALSE,
      model_type TEXT,
      provider TEXT,
      frameworks JSONB,
      decision TEXT,
      risk_score INT,
      risk_level TEXT,
      response_decision TEXT,
      response_risk_score INT,
      response_risk_level TEXT,
      finding_types JSONB,
      findings JSONB,
      business_hits JSONB,
      prompt_hash TEXT,
      protected_prompt TEXT,
      response_hash TEXT,
      protected_response TEXT,
      file_name TEXT,
      file_mime_type TEXT,
      file_size INT,
      extracted_text_length INT,
      grc JSONB,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_audit_events_created_at
    ON audit_events(created_at DESC);
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_audit_events_risk_level
    ON audit_events(risk_level);
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_audit_events_decision
    ON audit_events(decision);
  `);
}