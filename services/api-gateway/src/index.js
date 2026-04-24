import express from 'express';
import axios from 'axios';
import helmet from 'helmet';
import morgan from 'morgan';
import { createRemoteJWKSet, jwtVerify } from 'jose';

const app = express();

app.use(helmet());
app.use(express.json({ limit: '1mb' }));
app.use(morgan('dev'));

const PORT = process.env.PORT || 3000;

const OIDC_ISSUER = process.env.OIDC_ISSUER || 'http://keycloak:8080/realms/aigw';
const OIDC_CLIENT_ID = process.env.OIDC_CLIENT_ID || 'aigw-frontend';
const KEYCLOAK_TOKEN_URL =
  process.env.KEYCLOAK_TOKEN_URL ||
  'http://keycloak:8080/realms/aigw/protocol/openid-connect/token';

const LLM_URL = process.env.LLM_URL || 'http://llm-mock:3006';
const PROMPT_INSPECTOR_URL = process.env.PROMPT_INSPECTOR_URL || 'http://prompt-inspector:3001';
const RISK_ENGINE_URL = process.env.RISK_ENGINE_URL || 'http://risk-engine:3002';
const POLICY_ENGINE_URL = process.env.POLICY_ENGINE_URL || 'http://policy-engine:3003';
const LOGGER_GRC_URL = process.env.LOGGER_GRC_URL || 'http://logger-grc:3005';

const JWKS = createRemoteJWKSet(
  new URL(`${OIDC_ISSUER}/protocol/openid-connect/certs`)
);

app.get('/', (req, res) => {
  res.json({
    status: 'ok',
    service: 'api-gateway',
    iam: 'keycloak-oidc',
    modules: [
      'oidc',
      'rbac',
      'mfa',
      'prompt-inspector',
      'risk-engine',
      'policy-engine',
      'logger-grc'
    ]
  });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.post('/login/keycloak', async (req, res) => {
  try {
    const username = String(req.body.username || '');
    const password = String(req.body.password || '');

    if (!username || !password) {
      return res.status(400).json({
        error: 'missing_credentials'
      });
    }

    const body = new URLSearchParams();
    body.append('client_id', OIDC_CLIENT_ID);
    body.append('username', username);
    body.append('password', password);
    body.append('grant_type', 'password');

    const response = await axios.post(KEYCLOAK_TOKEN_URL, body, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });

    res.json(response.data);
  } catch (error) {
    res.status(401).json({
      error: 'keycloak_login_failed',
      details: error.response?.data || error.message
    });
  }
});

async function authenticateOidc(req, res, next) {
  const authHeader = req.headers.authorization || '';

  if (!authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'missing_token'
    });
  }

  const token = authHeader.replace('Bearer ', '');

  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: OIDC_ISSUER
    });

    if (payload.azp !== OIDC_CLIENT_ID) {
      return res.status(401).json({
        error: 'invalid_client',
        expected_client: OIDC_CLIENT_ID,
        received_client: payload.azp
      });
    }

    req.user = {
      subject: payload.sub,
      email: payload.email || payload.preferred_username,
      username: payload.preferred_username,
      roles: extractRoles(payload),
      department: payload.department || 'Security',
      country: payload.country || 'BE',
      raw: payload
    };

    next();
  } catch (error) {
    return res.status(401).json({
      error: 'invalid_token',
      message: error.message
    });
  }
}

function extractRoles(payload) {
  const realmRoles = payload.realm_access?.roles || [];

  const clientRoles = Object.values(payload.resource_access || {}).flatMap(
    resource => resource.roles || []
  );

  const groups = payload.groups || [];

  return [...new Set([...realmRoles, ...clientRoles, ...groups])];
}

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

function requireMfa(req, res, next) {
  const mfaVerified = String(req.headers['x-mfa-verified'] || '').toLowerCase();

  if (mfaVerified !== 'true') {
    return res.status(403).json({
      error: 'mfa_required'
    });
  }

  next();
}

async function writeAuditLog({
  user,
  originalPrompt,
  maskedPrompt,
  security,
  modelType,
  status
}) {
  try {
    await axios.post(`${LOGGER_GRC_URL}/audit`, {
      user,
      originalPrompt,
      maskedPrompt,
      security,
      modelType,
      status
    });
  } catch (error) {
    console.error('Audit logging failed:', error.message);
  }
}

app.get('/audit', async (req, res) => {
  try {
    const response = await axios.get(`${LOGGER_GRC_URL}/audit`);
    res.json(response.data);
  } catch (error) {
    res.status(502).json({
      error: 'audit_unavailable',
      details: error.message
    });
  }
});

app.post(
  '/v1/generate',
  authenticateOidc,
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

      const user = {
        email: req.user.email,
        username: req.user.username,
        roles: req.user.roles,
        department: req.user.department,
        country: req.user.country
      };

      const inspectorResponse = await axios.post(
        `${PROMPT_INSPECTOR_URL}/inspect`,
        { prompt }
      );

      const inspection = inspectorResponse.data;

      const riskResponse = await axios.post(`${RISK_ENGINE_URL}/score`, {
        findings: inspection.findings,
        modelType
      });

      const risk = riskResponse.data;

      const policyResponse = await axios.post(`${POLICY_ENGINE_URL}/evaluate`, {
        findings: inspection.findings,
        risk,
        modelType,
        user
      });

      const policy = policyResponse.data;

      const security = {
        sensitive: inspection.sensitive,
        findings: inspection.findings,
        risk,
        policy
      };

      const promptToSend =
        policy.action === 'masked'
          ? inspection.maskedPrompt || prompt
          : prompt;

      if (policy.action === 'blocked' || policy.action === 'approval_required') {
        await writeAuditLog({
          user,
          originalPrompt: prompt,
          maskedPrompt: promptToSend,
          security,
          modelType,
          status: policy.action
        });

        return res.status(403).json({
          status: policy.action,
          message: policy.reason,
          user,
          security
        });
      }

      const response = await axios.post(`${LLM_URL}/generate`, {
        prompt: promptToSend,
        modelType
      });

      await writeAuditLog({
        user,
        originalPrompt: prompt,
        maskedPrompt: promptToSend,
        security,
        modelType,
        status: 'success'
      });

      res.json({
        status: 'success',
        user,
        security,
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

app.use((req, res) => {
  res.status(404).json({
    error: 'not_found',
    path: req.originalUrl
  });
});

app.listen(PORT, () => {
  console.log(`api-gateway ready on port ${PORT}`);
});