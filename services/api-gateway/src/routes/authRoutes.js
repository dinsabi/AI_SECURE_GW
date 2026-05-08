import express from "express";
import { env } from "../config/env.js";

export const authRoutes = express.Router();

authRoutes.post("/login/keycloak", async (req, res) => {
  const username = req.body.username || req.body.email;
  const password = req.body.password;

  if (!username || !password) {
    return res.status(400).json({
      ok: false,
      error: "missing_credentials",
      message: "username/email and password are required",
    });
  }

  try {
    const params = new URLSearchParams();
    params.append("grant_type", "password");
    params.append("client_id", env.KEYCLOAK_CLIENT_ID);

    if (env.KEYCLOAK_CLIENT_SECRET) {
      params.append("client_secret", env.KEYCLOAK_CLIENT_SECRET);
    }

    params.append("username", username);
    params.append("password", password);

    const response = await fetch(
      `${env.KEYCLOAK_URL}/realms/${env.KEYCLOAK_REALM}/protocol/openid-connect/token`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: params.toString(),
      }
    );

    const data = await response.json();

    if (!response.ok) {
      return res.status(response.status).json({
        ok: false,
        error: "keycloak_login_failed",
        details: data,
      });
    }

    return res.json({
      ok: true,
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      token_type: data.token_type,
      expires_in: data.expires_in,
      refresh_expires_in: data.refresh_expires_in,
      scope: data.scope,
    });
  } catch (error) {
    return res.status(500).json({
      ok: false,
      error: "keycloak_unreachable",
      message: error.message,
    });
  }
});