import express from 'express';
import axios from 'axios';
import jwt from 'jsonwebtoken';
import helmet from 'helmet';
import morgan from 'morgan';

const app = express();

app.use(helmet());
app.use(express.json({ limit: '1mb' }));
app.use(morgan('dev'));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

const LLM_URL = process.env.LLM_URL || 'http://llm-mock:3006';
const PROMPT_INSPECTOR_URL = process.env.PROMPT_INSPECTOR_URL || 'http://prompt-inspector:3001';

// --------------------
// Health
// --------------------
app.get('/', (req, res) => {
  res.json({
    status: 'ok',
    service: 'api-gateway'
  });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// --------------------
// Mock login
// --------------------
app.post('/login/mock', (req, res) => {
  const {
    email = 'admin@cidns.eu',
    roles = ['admin'],
    department = 'Security',
    country = 'BE'
  } = req.body || {};

  const token = jwt.sign(
    {
      sub: email,
      email,
      roles,
      department,
      country
    },
    JWT_SECRET,
    { expiresIn: '1h' }
  );

  res.json({
    token,
    token_type: 'Bearer',
    expires_in: 3600
  });
});

// --------------------
// JWT middleware
// --------------------
function authenticateJwt(req, res, next) {
  const authHeader = req.headers.authorization || '';

  if (!authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'missing_token'
    });
  }

  const token = authHeader.replace('Bearer ', '');

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (error) {
    return res.status(401).json({
      error: 'invalid_token',
      message: error.message
    });
  }
}

// --------------------
// RBAC
// --------------------
function requireRole(allowedRoles = []) {
  return (req, res, next) => {
    const userRoles = req.user?.roles || [];

    const hasRole = userRoles.some(role => allowedRoles.includes(role));

    if (!hasRole) {
      return res.status(403).json({
        error: 'forbidden',
        required_roles: allowedRoles,
        user_roles: userRoles
      });
    }

    next();
  };
}

// --------------------
// MFA
// --------------------
function requireMfa(req, res, next) {
  const mfaVerified = String(req.headers['x-mfa-verified'] || '').toLowerCase();

  if (mfaVerified !== 'true') {
    return res.status(403).json({
      error: 'mfa_required'
    });
  }

  next();
}

// --------------------
// MAIN ENDPOINT
// --------------------
app.post(
  '/v1/generate',
  authenticateJwt,
  requireMfa,
  requireRole(['admin', 'security_architect', 'finance_manager']),
  async (req, res) => {
    try {
      const prompt = String(req.body.prompt || '');
      const modelType = String(req.body.modelType || 'public_llm');

      if (!prompt) {
        return res.status(400).json({
          error: 'missing_prompt'
        });
      }

      // --------------------
      // 1. Inspect prompt
      // --------------------
      const inspectorResponse = await axios.post(
        `${PROMPT_INSPECTOR_URL}/inspect`,
        { prompt }
      );

      const inspection = inspectorResponse.data;

      const promptToSend = inspection.maskedPrompt || prompt;

      console.log('Inspection result:', inspection);

      // --------------------
      // 2. Call LLM
      // --------------------
      const response = await axios.post(`${LLM_URL}/generate`, {
        prompt: promptToSend,
        modelType
      });

      // --------------------
      // 3. Return enriched response
      // --------------------
      res.json({
        status: 'success',

        user: {
          email: req.user.email,
          roles: req.user.roles,
          department: req.user.department,
          country: req.user.country
        },

        security: {
          sensitive: inspection.sensitive,
          findings: inspection.findings,
          action: inspection.sensitive ? 'masked' : 'allowed'
        },

        provider_response: response.data
      });

    } catch (error) {
      console.error('Gateway error:', error.message);

      res.status(502).json({
        error: 'upstream_error',
        details: error.message
      });
    }
  }
);

// --------------------
// 404
// --------------------
app.use((req, res) => {
  res.status(404).json({
    error: 'not_found',
    path: req.originalUrl
  });
});

// --------------------
app.listen(PORT, () => {
  console.log(`api-gateway ready on port ${PORT}`);
});