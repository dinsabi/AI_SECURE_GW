# AI Secure Gateway - 12 modules

Application PHP de démonstration structurée en multi-fichiers.

Modules inclus :
1. IAM Adapter
2. Prompt Inspection
3. Masking / Tokenization
4. Policy Engine
5. Risk Scoring
6. Decision Engine
7. LLM Routing
8. Secure RAG
9. Response Filtering
10. Audit & Compliance
11. Dashboard & Governance
12. Connectors

## Démarrage
```bash
php -S 0.0.0.0:8080 -t public
```

## Endpoints
- GET /
- POST /gateway/process
- GET /dashboard/summary
- GET /connectors
- POST /rag/query
