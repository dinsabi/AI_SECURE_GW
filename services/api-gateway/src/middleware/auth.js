export function readUserFromHeaders(req) {
  return {
    email: req.headers["x-user-email"] || "admin@cidns.eu",
    department: req.headers["x-user-department"] || "Unknown",
    roles: req.headers["x-user-roles"] || "user",
    country: req.headers["x-user-country"] || "BE",
    mfaVerified: req.headers["x-mfa-verified"] || "false",
  };
}

export function extractBearerToken(req) {
  const auth = req.headers.authorization || "";
  return auth.startsWith("Bearer ") ? auth.substring("Bearer ".length) : null;
}

export function requireAuth(req, res, next) {
  const token = extractBearerToken(req);

  if (!token) {
    return res.status(401).json({
      ok: false,
      error: "missing_token",
      message: "Missing Authorization Bearer token",
    });
  }

  req.token = token;
  next();
}