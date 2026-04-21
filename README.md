# AI Security Platform — LLD MVP

Plateforme IA de type microservices, exploitable en local avec Docker Compose.

## Stack
- API Gateway: Nginx
- Backend / orchestration: Node.js (Express)
- Microservices:
  - api-gateway
  - prompt-inspector
  - risk-engine
  - policy-engine
  - response-analyzer
  - logger-grc
  - llm-mock
- Data:
  - PostgreSQL pour les logs/audit
  - Elasticsearch pour search/SIEM
- Infra:
  - Docker / Docker Compose

## Flow technique
1. User envoie prompt
2. Authentification IAM (mock via headers)
3. Inspection prompt
4. Scoring risque
5. Policy decision: allow / mask / block
6. Envoi au LLM
7. Analyse réponse
8. Logging + GRC

## Démarrage
```bash
docker compose up --build
```

## Endpoint principal
```bash
POST http://localhost:8080/v1/prompt/process
```
