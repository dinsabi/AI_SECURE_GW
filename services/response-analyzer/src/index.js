import express from 'express';
const app = express();
app.use(express.json());

app.post('/analyze', (req, res) => {
  const answer = String(req.body.llmResponse?.answer || '');
  const flags = [];
  if (/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i.test(answer)) flags.push('potential_data_leak');
  if (/\b(always|guaranteed|100% certain)\b/i.test(answer)) flags.push('possible_hallucination');
  if (/\b(drop database|bypass security|delete all)\b/i.test(answer)) flags.push('dangerous_content');
  res.json({ flags, responseDecision: flags.includes('dangerous_content') ? 'block' : 'allow' });
});
app.listen(process.env.PORT || 3004, () => console.log('response-analyzer ready'));
