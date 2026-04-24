import express from 'express';

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3003;

app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'policy-engine' });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.post('/evaluate', (req, res) => {
  const risk = req.body.risk || {};
  const findings = req.body.findings || [];
  const modelType = req.body.modelType || 'public_llm';

  let action = 'allowed';
  let reason = 'Low risk request allowed';

  if (risk.level === 'LOW') {
    action = 'allowed';
    reason = 'Low risk request allowed';
  }

  if (risk.level === 'MEDIUM') {
    action = 'masked';
    reason = 'Medium risk request: sensitive data must be masked';
  }

  if (risk.level === 'HIGH') {
    action = 'approval_required';
    reason = 'High risk request requires security approval';
  }

  if (findings.includes('api_key')) {
    action = 'blocked';
    reason = 'API keys or secrets must never be sent to an LLM';
  }

  if (findings.includes('iban') && modelType === 'public_llm') {
    action = 'masked';
    reason = 'IBAN detected: masking required before public LLM usage';
  }

  res.json({
    action,
    reason,
    policy: 'NIS2-AI-GATEWAY-POLICY',
    framework: ['NIS2', 'ISO27001', 'GDPR']
  });
});

app.listen(PORT, () => {
  console.log(`policy-engine ready on port ${PORT}`);
});