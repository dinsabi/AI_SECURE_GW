import express from 'express';
import pg from 'pg';

const { Pool } = pg;

const app = express();
app.use(express.json({ limit: '2mb' }));

const PORT = process.env.PORT || 3005;

const pool = new Pool({
  host: process.env.PGHOST || 'postgres',
  port: Number(process.env.PGPORT || 5432),
  database: process.env.PGDATABASE || 'aigw',
  user: process.env.PGUSER || 'aigw',
  password: process.env.PGPASSWORD || 'aigwpass'
});

app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'logger-grc' });
});

app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', database: 'connected' });
  } catch (error) {
    res.status(500).json({ status: 'error', details: error.message });
  }
});

app.post('/audit', async (req, res) => {
  try {
    const {
      user = {},
      originalPrompt = '',
      maskedPrompt = '',
      security = {},
      modelType = 'public_llm',
      status = 'unknown'
    } = req.body;

    const findings = security.findings || [];
    const risk = security.risk || {};
    const policy = security.policy || {};

    const result = await pool.query(
      `
      INSERT INTO audit_logs (
        user_email,
        user_roles,
        department,
        country,
        original_prompt,
        masked_prompt,
        findings,
        sensitive,
        risk_score,
        risk_level,
        policy_action,
        policy_reason,
        model_type,
        status
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
      RETURNING id, timestamp
      `,
      [
        user.email || null,
        Array.isArray(user.roles) ? user.roles.join(',') : '',
        user.department || null,
        user.country || null,
        originalPrompt,
        maskedPrompt,
        findings.join(','),
        Boolean(security.sensitive),
        risk.score || 0,
        risk.level || 'UNKNOWN',
        policy.action || 'unknown',
        policy.reason || '',
        modelType,
        status
      ]
    );

    res.status(201).json({
      status: 'logged',
      id: result.rows[0].id,
      timestamp: result.rows[0].timestamp
    });
  } catch (error) {
    console.error('Audit log error:', error.message);
    res.status(500).json({
      error: 'audit_log_failed',
      details: error.message
    });
  }
});

app.get('/audit', async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT *
      FROM audit_logs
      ORDER BY timestamp DESC
      LIMIT 50
      `
    );

    res.json({
      count: result.rows.length,
      logs: result.rows
    });
  } catch (error) {
    res.status(500).json({
      error: 'audit_read_failed',
      details: error.message
    });
  }
});

app.listen(PORT, () => {
  console.log(`logger-grc ready on port ${PORT}`);
});