import express from 'express';
import axios from 'axios';

const app = express();
app.use(express.json());

app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'api-gateway' });
});

app.post('/v1/generate', async (req, res) => {
  try {
    const prompt = String(req.body.prompt || '');
    const modelType = String(req.body.modelType || 'public_llm');

    const response = await axios.post(`${process.env.LLM_URL}/generate`, {
      prompt,
      modelType
    });

    res.json(response.data);
  } catch (error) {
    console.error('Gateway error:', error.message);
    res.status(502).json({ error: 'Upstream LLM unavailable', details: error.message });
  }
});

app.listen(process.env.PORT || 3000, () => {
  console.log(`api-gateway ready on port ${process.env.PORT || 3000}`);
});