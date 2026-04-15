<?php
declare(strict_types=1);
namespace App\Modules;

use App\Domain\UserContext;
use App\Infrastructure\AuditLogger;
use App\Infrastructure\JsonStore;

final class IamModule {
    public function authenticate(UserContext $u): array {
        if ($u->email === '') return ['ok' => false, 'reason' => 'Email requis'];
        if ($u->roles === []) return ['ok' => false, 'reason' => 'Aucun rôle'];
        if (!$u->mfaVerified) return ['ok' => false, 'reason' => 'MFA requise'];
        $segment = match (strtolower($u->department)) { 'finance' => 'Finance', 'hr', 'human resources' => 'HR', 'it', 'security' => 'IT', default => 'General' };
        return ['ok' => true, 'segment' => $segment, 'reason' => 'Authentifié'];
    }
}

final class InspectionModule {
    public function inspect(string $prompt): array {
        $score = 0.0; $cats = []; $findings = [];
        $rules = [
            ['type' => 'email', 'category' => 'pii', 'score' => 8.0, 'pattern' => '/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i'],
            ['type' => 'iban', 'category' => 'pii', 'score' => 18.0, 'pattern' => '/\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/'],
            ['type' => 'secret', 'category' => 'secret', 'score' => 25.0, 'pattern' => "/\b(?:password|passwd|pwd|secret|client_secret|token)\s*[:=]/i"],
            ['type' => 'business_sensitive', 'category' => 'business_sensitive', 'score' => 12.0, 'pattern' => '/\b(contract|salary|customer list|bank account|source code|repository)\b/i'],
            ['type' => 'person_name_like', 'category' => 'pii', 'score' => 5.0, 'pattern' => '/\b([A-Z][a-z]{2,}\s+[A-Z][a-z]{2,})\b/u'],
        ];
        foreach ($rules as $rule) {
            if (preg_match_all($rule['pattern'], $prompt, $m, PREG_OFFSET_CAPTURE)) {
                foreach ($m[0] as [$match, $offset]) {
                    $score += $rule['score']; $cats[] = $rule['category'];
                    $findings[] = ['type' => $rule['type'], 'category' => $rule['category'], 'match' => (string)$match, 'position' => (int)$offset];
                }
            }
        }
        $cats = array_values(array_unique($cats));
        $classification = $score >= 45 ? 'critical' : ($score >= 20 ? 'confidential' : 'public');
        $action = in_array('secret', $cats, true) ? 'block' : ($classification !== 'public' ? 'mask_or_review' : 'allow');
        return ['findings' => $findings, 'classification' => $classification, 'risk_score' => $score, 'categories' => $cats, 'recommended_action' => $action];
    }
}

final class MaskingModule {
    public function __construct(private readonly JsonStore $vault) {}
    public function process(string $prompt, string $mode): array {
        $vault = $this->vault->read(); $processed = $prompt; $repls = []; $counter = count($vault);
        $rules = [
            ['type' => 'email', 'pattern' => '/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i'],
            ['type' => 'iban', 'pattern' => '/\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/'],
            ['type' => 'secret', 'pattern' => "/\b(?:password|passwd|pwd|secret|client_secret|token)\s*[:=]\s*[^\s]+/i"],
            ['type' => 'person', 'pattern' => '/\b([A-Z][a-z]{2,}\s+[A-Z][a-z]{2,})\b/u'],
        ];
        foreach ($rules as $rule) {
            if (preg_match_all($rule['pattern'], $processed, $m)) {
                foreach ($m[0] as $match) {
                    if ($mode === 'tokenize') {
                        if (!isset($vault[$match])) { $counter++; $vault[$match] = '[' . strtoupper($rule['type']) . '_' . str_pad((string)$counter, 3, '0', STR_PAD_LEFT) . ']'; }
                        $replacement = $vault[$match];
                    } else {
                        $replacement = '[' . strtoupper($rule['type']) . '_REDACTED]';
                    }
                    $processed = str_replace($match, $replacement, $processed);
                    $repls[] = ['original' => $match, 'replacement' => $replacement, 'type' => $rule['type']];
                }
            }
        }
        $this->vault->write($vault);
        return ['mode' => $mode, 'processed_text' => $processed, 'replacement_count' => count($repls), 'replacements' => $repls, 'vault_size' => count($vault)];
    }
}

final class PolicyModule {
    public function evaluate(UserContext $u, array $insp, string $modelType, array $frameworks): array {
        $decision = 'allow'; $oblig = []; $reasons = []; $frameworks = array_values(array_unique(array_map('strtoupper', $frameworks)));
        if (($insp['classification'] ?? 'public') === 'critical' && $modelType === 'public_llm') { $decision = 'block'; $oblig[] = 'use_private_model'; $reasons[] = 'Données critiques interdites sur modèle public.'; }
        if ($u->department === 'Finance' && $modelType === 'public_llm' && $decision !== 'block') { $decision = 'tokenize'; $oblig[] = 'tokenize_sensitive_fields'; $reasons[] = 'Finance sur modèle public : tokenisation obligatoire.'; }
        if ($u->department === 'HR' && in_array(($insp['classification'] ?? 'public'), ['confidential','critical'], true) && !in_array($decision, ['block','tokenize'], true)) { $decision = 'mask'; $oblig[] = 'mask_sensitive_fields'; $reasons[] = 'RH + données non publiques : masquage requis.'; }
        if (in_array('NIS2', $frameworks, true) && $modelType === 'public_llm' && in_array(($insp['classification'] ?? 'public'), ['confidential','critical'], true) && $decision !== 'block') { $decision = 'review'; $oblig[] = 'security_review'; $reasons[] = 'NIS2 impose une revue.'; }
        if (in_array('GDPR', $frameworks, true) && in_array('pii', $insp['categories'] ?? [], true) && $decision === 'allow') { $decision = 'mask'; $oblig[] = 'minimize_personal_data'; $reasons[] = 'GDPR impose la minimisation.'; }
        if (in_array('ISO27001', $frameworks, true)) { $oblig[] = 'log_event'; $reasons[] = 'ISO 27001 exige la traçabilité.'; }
        if ($reasons === []) $reasons[] = 'Aucune règle bloquante détectée.';
        return ['decision' => $decision, 'obligations' => array_values(array_unique($oblig)), 'frameworks' => $frameworks, 'reasons' => array_values(array_unique($reasons))];
    }
}

final class RiskScoringModule {
    public function score(UserContext $u, array $insp): array {
        $score = (float)($insp['risk_score'] ?? 0); if ($u->deviceTrust !== 'managed') $score += 10; if (!in_array($u->country, ['BE','FR','DE','NL','LU'], true)) $score += 7; if (in_array('secret', $insp['categories'] ?? [], true)) $score += 20; if (in_array($u->department, ['Finance','HR'], true)) $score += 5;
        $level = $score >= 60 ? 'HIGH' : ($score >= 30 ? 'MEDIUM' : 'LOW');
        return ['score' => round($score,2), 'level' => $level];
    }
}

final class DecisionModule {
    public function decide(array $policy, array $risk): array {
        $p = $policy['decision'] ?? 'allow'; $r = $risk['level'] ?? 'LOW';
        $final = match (true) { $p === 'block' => 'BLOCK', $p === 'review' => 'ESCALATE', in_array($p, ['mask','tokenize'], true) => 'MASK', $r === 'HIGH' => 'ESCALATE', default => 'ALLOW' };
        return ['final' => $final, 'policy_decision' => $p, 'risk_level' => $r];
    }
}

final class RoutingModule {
    public function __construct(private readonly array $providers) {}
    public function route(string $requestedModelType, string $decision): array {
        $selected = $requestedModelType; $fallback = null;
        if ($decision === 'MASK' && $requestedModelType === 'public_llm') { $selected = 'private_llm'; $fallback = 'internal_rag'; }
        if (in_array($decision, ['BLOCK','ESCALATE'], true)) $selected = 'none';
        return ['requested_model_type' => $requestedModelType, 'selected_model_type' => $selected, 'provider' => $selected !== 'none' ? ($this->providers[$selected] ?? 'unknown') : 'none', 'fallback' => $fallback];
    }
}

final class RagModule {
    public function __construct(private readonly JsonStore $store) {
        if ($this->store->read() === []) {
            $this->store->write([
                'doc-001' => ['title' => 'Finance Policy', 'access' => ['Finance','IT'], 'content' => 'Finance policy for procurement and budget control.'],
                'doc-002' => ['title' => 'HR Guide', 'access' => ['HR'], 'content' => 'HR internal rules for employee records and evaluations.'],
                'doc-003' => ['title' => 'Security Standard', 'access' => ['IT','Finance','HR'], 'content' => 'Security baseline aligned with NIS2 and ISO 27001.'],
            ]);
        }
    }
    public function query(UserContext $u, array $docIds): array {
        $index = $this->store->read(); $results = [];
        foreach ($docIds as $id) {
            $doc = $index[$id] ?? null; if ($doc === null) continue; if (!in_array($u->department, $doc['access'], true)) continue;
            $results[] = ['document_id' => $id, 'title' => $doc['title'], 'snippet' => $doc['content']];
        }
        return ['document_count' => count($results), 'results' => $results];
    }
}

final class ResponseFilteringModule {
    public function filter(array $llm): array {
        $answer = (string)($llm['answer'] ?? ''); $flags = [];
        if (preg_match('/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i', $answer)) { $flags[] = 'possible_data_leak'; $answer = preg_replace('/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i', '[EMAIL_REDACTED]', $answer) ?? $answer; }
        if (preg_match('/\b(drop database|delete all|bypass security)\b/i', $answer)) $flags[] = 'dangerous_content';
        if (preg_match('/\b(always|guaranteed|100% certain)\b/i', $answer)) $flags[] = 'possible_hallucination';
        return ['filtered_answer' => $answer, 'flags' => array_values(array_unique($flags)), 'blocked' => in_array('dangerous_content', $flags, true)];
    }
}

final class AuditComplianceModule {
    public function __construct(private readonly AuditLogger $audit) {}
    public function record(string $event, array $context = []): array { return $this->audit->record($event, $context); }
    public function exportReadyStatus(): array { return ['nis2_ready' => true, 'gdpr_ready' => true, 'iso27001_ready' => true]; }
}

final class DashboardModule {
    public function __construct(private readonly JsonStore $store) {}
    public function update(array $decision, array $risk): array {
        $d = $this->store->read(); if ($d === []) $d = ['total_prompts' => 0, 'blocked_prompts' => 0, 'masked_prompts' => 0, 'escalated_prompts' => 0, 'risk_sum' => 0.0];
        $d['total_prompts']++; if (($decision['final'] ?? '') === 'BLOCK') $d['blocked_prompts']++; if (($decision['final'] ?? '') === 'MASK') $d['masked_prompts']++; if (($decision['final'] ?? '') === 'ESCALATE') $d['escalated_prompts']++; $d['risk_sum'] += (float)($risk['score'] ?? 0);
        $this->store->write($d); return $this->summary();
    }
    public function summary(): array {
        $d = $this->store->read(); $total = (int)($d['total_prompts'] ?? 0); $avg = $total > 0 ? round(((float)($d['risk_sum'] ?? 0)) / $total, 2) : 0.0;
        return ['kpis' => ['total_prompts' => $total, 'blocked_prompts' => (int)($d['blocked_prompts'] ?? 0), 'masked_prompts' => (int)($d['masked_prompts'] ?? 0), 'escalated_prompts' => (int)($d['escalated_prompts'] ?? 0), 'average_risk' => $avg], 'soc_view' => ['alerting' => ((int)($d['blocked_prompts'] ?? 0) > 0) || ((int)($d['escalated_prompts'] ?? 0) > 0)]];
    }
}

final class ConnectorsModule {
    public function __construct(private readonly array $connectors) {}
    public function list(): array { return ['connectors' => array_map(static fn(string $n) => ['name' => $n, 'enabled' => true], $this->connectors)]; }
}
