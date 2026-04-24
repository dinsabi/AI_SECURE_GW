import express from 'express';

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3001;

function inspectPrompt(prompt) {
  const findings = [];

  let maskedPrompt = prompt;

  const emailRegex = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi;
  const ibanRegex = /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g;
  const apiKeyRegex = /\b(sk-[A-Za-z0-9_-]{20,}|api[_-]?key\s*[:=]\s*[A-Za-z0-9_-]{16,})\b/gi;

  if (emailRegex.test(prompt)) {
    findings.push('email');
    maskedPrompt = maskedPrompt.replace(emailRegex, '[EMAIL]');
  }

  if (ibanRegex.test(prompt)) {
    findings.push('iban');
    maskedPrompt = maskedPrompt.replace(ibanRegex, '[IBAN]');
  }

  if (apiKeyRegex.test(prompt)) {
    findings.push('api_key');
    maskedPrompt = maskedPrompt.replace(apiKeyRegex, '[API_KEY]');
  }

  return {
    sensitive: findings.length > 0,
    findings,
    maskedPrompt
  };
}

app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'prompt-inspector' });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.post('/inspect', (req, res) => {
  const prompt = String(req.body.prompt || '');

  if (!prompt) {
    return res.status(400).json({
      error: 'missing_prompt'
    });
  }

  res.json(inspectPrompt(prompt));
});

app.listen(PORT, () => {
  console.log(`prompt-inspector ready on port ${PORT}`);
});