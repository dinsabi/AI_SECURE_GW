import express from 'express';
const app = express();
app.use(express.json());

function maskPrompt(prompt) {
  return prompt
    .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, '[EMAIL_REDACTED]')
    .replace(/\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g, '[IBAN_REDACTED]');
}

app.post('/inspect', (req, res) => {
  const prompt = String(req.body.prompt || '');
  const findings = [];
  if (/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i.test(prompt)) findings.push({ type: 'email', category: 'pii', severity: 'medium' });
  if (/\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/.test(prompt)) findings.push({ type: 'iban', category: 'pii', severity: 'high' });
  if (/\b(password|passwd|pwd|secret|token|client_secret)\s*[:=]/i.test(prompt)) findings.push({ type: 'secret', category: 'secret', severity: 'critical' });
  if (/\b(contract|salary|customer list|bank account|source code|repository)\b/i.test(prompt)) findings.push({ type: 'business_sensitive', category: 'business', severity: 'high' });

  const categories = [...new Set(findings.map(f => f.category))];
  let classification = 'public';
  if (findings.some(f => f.severity === 'critical')) classification = 'critical';
  else if (findings.length > 0) classification = 'confidential';

  res.json({ findings, categories, classification, maskedPrompt: maskPrompt(prompt) });
});
app.listen(process.env.PORT || 3001, () => console.log('prompt-inspector ready'));
