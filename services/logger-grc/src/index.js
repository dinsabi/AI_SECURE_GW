import express from 'express';
import pg from 'pg';
const { Pool } = pg;
const app = express();
app.use(express.json());

const pool = new Pool({
  host: process.env.PGHOST,
  port: Number(process.env.PGPORT || 5432),
  database: process.env.PGDATABASE,
  user: process.env.PGUSER,
  password: process.env.PGPASSWORD,
});

app.post('/log', async (req, res) => {
  const traceId = String(req.body.traceId || 'unknown');
  try {
    await pool.query(
      'INSERT INTO audit_events (trace_id, event_type, severity, payload) VALUES ($1, $2, $3, $4::jsonb)',
      [traceId, 'prompt_processed', 'INFO', JSON.stringify(req.body)]
    );
    res.json({ persisted: true, traceId, sink: ['postgres', 'elastic_placeholder'] });
  } catch (err) {
    res.status(500).json({ persisted: false, traceId, error: err.message });
  }
});
app.listen(process.env.PORT || 3005, () => console.log('logger-grc ready'));
