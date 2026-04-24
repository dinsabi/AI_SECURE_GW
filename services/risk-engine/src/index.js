import express from 'express';

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3002;

app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'risk-engine' });
});

app.post('/score', (req, res) => {
  const findings = req.body.findings || [];
  const modelType = req.body.modelType || 'public_llm';

  let score = 10;

  if (findings.includes('email')) score += 20;
  if (findings.includes('iban')) score += 35;
  if (findings.includes('api_key')) score += 50;
  if (modelType === 'public_llm') score += 15;

  score = Math.min(score, 100);

  let level = 'LOW';
  if (score >= 70) level = 'HIGH';
  else if (score >= 40) level = 'MEDIUM';

  res.json({
    score,
    level,
    framework: 'NIS2',
    recommendation:
      level === 'HIGH'
        ? 'Block or require security approval'
        : level === 'MEDIUM'
        ? 'Mask sensitive data before sending'
        : 'Allow request'
  });
});

app.listen(PORT, () => {
  console.log(`risk-engine ready on port ${PORT}`);
});