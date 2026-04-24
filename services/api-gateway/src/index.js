import express from 'express';
import axios from 'axios';
import jwt from 'jsonwebtoken';

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

// --------------------
// Health check
// --------------------
app.get('/', (req, res) => {
  res.json({
    status: 'ok',
    service: 'api-gateway'
  });
});

app.get('/health', (req, res) => {
  res.json({
    status: 'ok'
  });
});

// --------------------
// Mock login pour générer un JWT de test
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
// Middleware JWT
// --------------------
function authenticateJwt(req, res, next) {
  const authHeader = req.headers.authorization || '';

  if (!authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'missing_token',
      message: 'Authorization header Bearer token is required'
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
// Middleware RBAC
// --------------------
function requireRole(allowedRoles = []) {
  return (req, res, next) => {
    const userRoles = req.user?.roles || [];

    const hasRole = userRoles.some(role => allowedRoles.includes(role));

    if (!hasRole) {
      return res.status(403).json({
        error: 'forbidden',
        message: 'User does not have required role',
        required_roles: allowedRoles,
        user_roles: userRoles
      });
    }

    next();
  };
}

// --------------------
// Middleware MFA header
// --------------------
function requireMfa(req, res, next) {
  const mfaVerified = String(req.headers['x-mfa-verified'] || '').toLowerCase();

  if (mfaVerified !== 'true') {
    return res.status(403).json({
      error: 'mfa_required',
      message: 'MFA verification is required. Send header X-MFA-Verified: true'
    });
  }

  next();
}

// --------------------
// Endpoint protégé
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
          error: 'missing_prompt',
          message: 'prompt is required'
        });
      }

      console.log('Authenticated user:', {
        email: req.user.email,
        roles: req.user.roles,
        department: req.user.department,
        country: req.user.country
      });

      const response = await axios.post(`${process.env.LLM_URL}/generate`, {
        prompt,
        modelType
      });

      res.json({
        user: {
          email: req.user.email,
          roles: req.user.roles,
          department: req.user.department,
          country: req.user.country
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

app.listen(PORT, () => {
  console.log(`api-gateway ready on port ${PORT}`);
});