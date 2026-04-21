import express from 'express';
const app = express();
app.use(express.json());

app.post('/decide', (req, res) => {
  const { user, inspection, risk, modelType, frameworks } = req.body;
  let action = 'allow';
  const reasons = [];

  if (inspection.classification === 'critical' && modelType === 'public_llm') {
    action = 'block';
    reasons.push('Critical data cannot be sent to public LLM');
  } else if ((user.department === 'Finance' || user.department === 'HR') && inspection.classification !== 'public') {
    action = 'mask';
    reasons.push('Sensitive department requires masking');
  }
  if ((frameworks || []).includes('NIS2') && risk.level === 'HIGH') {
    action = 'block';
    reasons.push('NIS2 high-risk block');
  }
  if ((frameworks || []).includes('GDPR') && (inspection.categories || []).includes('pii') && action === 'allow') {
    action = 'mask';
    reasons.push('GDPR requires PII minimization');
  }

  res.json({ action, reasons });
});
app.listen(process.env.PORT || 3003, () => console.log('policy-engine ready'));
