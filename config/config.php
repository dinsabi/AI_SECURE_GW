<?php
declare(strict_types=1);
return [
  'llm' => ['endpoint' => 'https://example-llm-gateway.local/v1/chat/completions', 'api_key' => 'replace-me'],
  'storage' => [
    'audit' => __DIR__ . '/../var/audit.log',
    'vault' => __DIR__ . '/../var/token_vault.json',
    'dashboard' => __DIR__ . '/../var/dashboard.json',
    'rag' => __DIR__ . '/../var/rag_index.json',
  ],
  'routing' => ['public_llm' => 'openai_public', 'private_llm' => 'azure_private', 'internal_rag' => 'internal_rag'],
  'connectors' => ['Teams', 'Slack', 'Browser Extension', 'Enterprise API', 'Git', 'CI/CD'],
];
