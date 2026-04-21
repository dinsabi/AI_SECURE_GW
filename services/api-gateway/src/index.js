import express from 'express';
const app = express();
app.use(express.json());

app.post('/generate', (req, res) => {
  const prompt = String(req.body.prompt || '');
  const modelType = String(req.body.modelType || 'public_llm');
  res.json({ provider: 'mock-llm', modelType, answer: `Réponse mock du LLM pour: ${prompt.slice(0, 120)}` });
});
app.listen(process.env.PORT || 3006, () => console.log('llm-mock ready'));
