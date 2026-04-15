<?php
declare(strict_types=1);
namespace App\Application;

use App\Domain\GatewayRequest;
use App\Infrastructure\LlmConnector;
use App\Modules\AllModules\AuditComplianceModule;
use App\Modules\AllModules\ConnectorsModule;
use App\Modules\AllModules\DashboardModule;
use App\Modules\AllModules\DecisionModule;
use App\Modules\AllModules\IamModule;
use App\Modules\AllModules\InspectionModule;
use App\Modules\AllModules\MaskingModule;
use App\Modules\AllModules\PolicyModule;
use App\Modules\AllModules\RagModule;
use App\Modules\AllModules\ResponseFilteringModule;
use App\Modules\AllModules\RiskScoringModule;
use App\Modules\AllModules\RoutingModule;

final class ProcessGatewayRequest {
    public function __construct(
        private readonly IamModule $iam,
        private readonly InspectionModule $inspection,
        private readonly MaskingModule $masking,
        private readonly PolicyModule $policy,
        private readonly RiskScoringModule $risk,
        private readonly DecisionModule $decision,
        private readonly RoutingModule $routing,
        private readonly RagModule $rag,
        private readonly ResponseFilteringModule $responseFiltering,
        private readonly AuditComplianceModule $auditCompliance,
        private readonly DashboardModule $dashboard,
        private readonly ConnectorsModule $connectors,
        private readonly LlmConnector $llmConnector,
    ) {}
    public function execute(array $payload): array {
        $req = GatewayRequest::fromArray($payload); if ($req->prompt === '') throw new \RuntimeException('Prompt requis.');
        $audit = [];
        $audit[] = $this->auditCompliance->record('gateway.request.received', ['user' => $req->user->email, 'model_type' => $req->modelType]);
        $iam = $this->iam->authenticate($req->user); $audit[] = $this->auditCompliance->record('module.iam', $iam); if (!($iam['ok'] ?? false)) throw new \RuntimeException((string)($iam['reason'] ?? 'IAM denied'));
        $inspection = $this->inspection->inspect($req->prompt); $audit[] = $this->auditCompliance->record('module.inspection', $inspection);
        $rag = $req->documentIds !== [] ? $this->rag->query($req->user, $req->documentIds) : null;
        if ($rag !== null) $audit[] = $this->auditCompliance->record('module.rag', ['document_count' => $rag['document_count']]);
        $policy = $this->policy->evaluate($req->user, $inspection, $req->modelType, $req->frameworks); $audit[] = $this->auditCompliance->record('module.policy', $policy);
        $risk = $this->risk->score($req->user, $inspection); $audit[] = $this->auditCompliance->record('module.risk', $risk);
        $decision = $this->decision->decide($policy, $risk); $audit[] = $this->auditCompliance->record('module.decision', $decision);
        $masking = null; $finalPrompt = $req->prompt;
        if (($decision['final'] ?? '') === 'MASK') {
            $mode = ($policy['decision'] ?? 'mask') === 'tokenize' ? 'tokenize' : 'mask';
            $masking = $this->masking->process($req->prompt, $mode); $finalPrompt = $masking['processed_text'];
            $audit[] = $this->auditCompliance->record('module.masking', ['mode' => $mode, 'replacement_count' => $masking['replacement_count']]);
        }
        if (($decision['final'] ?? '') === 'ESCALATE') {
            $masking = $masking ?? $this->masking->process($req->prompt, 'mask'); $finalPrompt = $masking['processed_text'];
            $audit[] = $this->auditCompliance->record('module.masking', ['mode' => 'mask', 'replacement_count' => $masking['replacement_count']]);
        }
        if ($rag !== null && ($rag['document_count'] ?? 0) > 0) {
            $finalPrompt .= "\n\nContexte RAG:\n" . implode("\n", array_map(static fn(array $r) => $r['snippet'], $rag['results']));
        }
        $routing = $this->routing->route($req->modelType, $decision['final']); $audit[] = $this->auditCompliance->record('module.routing', $routing);
        $llm = null; $responseFilter = null;
        if (($decision['final'] ?? '') !== 'BLOCK' && ($decision['final'] ?? '') !== 'ESCALATE' && $req->callLlm && ($routing['selected_model_type'] ?? 'none') !== 'none') {
            $llm = $this->llmConnector->send($finalPrompt, (string)$routing['provider'], (string)$routing['selected_model_type']);
            $audit[] = $this->auditCompliance->record('module.llm', ['ok' => $llm['ok'] ?? true, 'provider' => $routing['provider'] ?? 'unknown']);
            if (($llm['ok'] ?? false) || (($llm['simulated'] ?? false) === true)) {
                $responseFilter = $this->responseFiltering->filter($llm);
                $audit[] = $this->auditCompliance->record('module.response_filtering', $responseFilter);
            }
        }
        $audit[] = $this->auditCompliance->record('module.compliance', $this->auditCompliance->exportReadyStatus());
        $dashboard = $this->dashboard->update($decision, $risk); $audit[] = $this->auditCompliance->record('module.dashboard', $dashboard['kpis']);
        $connectors = $this->connectors->list(); $audit[] = $this->auditCompliance->record('module.connectors', ['count' => count($connectors['connectors'])]);
        return ['iam' => $iam, 'inspection' => $inspection, 'masking' => $masking, 'policy' => $policy, 'risk' => $risk, 'decision' => $decision, 'routing' => $routing, 'rag' => $rag, 'llm' => $llm, 'response_filter' => $responseFilter, 'audit' => $audit, 'dashboard' => $dashboard, 'final_prompt' => $finalPrompt];
    }
}
