const express = require('express');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());

// --- HEALTH CHECK ---
app.get('/', (req, res) => {
  res.status(200).json({
    status: 'OK',
    service: 'AI Secure Gateway',
    version: '1.0'
  });
});

// --- OPTIONAL HEALTH V1 ---
app.get('/v1', (req, res) => {
  res.status(200).json({
    status: 'OK',
    message: 'API v1 is running'
  });
});

// --- MAIN ENDPOINT ---
app.post('/v1/generate', async (req, res) => {
  try {
    const { prompt, modelType } = req.body;

    if (!prompt) {
      return res.status(400).json({
        error: 'Prompt is required'
      });
    }

    console.log('📥 Incoming request:', { prompt, modelType });

    // Call LLM mock service
    const llmResponse = await axios.post(
      `${process.env.LLM_URL}/generate`,
      {
        prompt,
        modelType
      }
    );

    console.log('📤 LLM response received');

    return res.status(200).json({
      success: true,
      data: llmResponse.data
    });

  } catch (error) {
    console.error('❌ Error:', error.message);

    return res.status(500).json({
      error: 'Internal server error',
      details: error.message
    });
  }
});

// --- SAMPLE OTHER ROUTES ---
app.get('/dashboard/summary', (req, res) => {
  res.json({
    users: 10,
    requests: 120,
    riskLevel: 'LOW'
  });
});

app.get('/connectors', (req, res) => {
  res.json([
    { name: 'LLM Mock', status: 'connected' },
    { name: 'Policy Engine', status: 'connected' }
  ]);
});

// --- START SERVER ---
app.listen(PORT, () => {
  console.log(`🚀 API Gateway running on port ${PORT}`);
});
