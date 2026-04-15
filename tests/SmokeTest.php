<?php
declare(strict_types=1);
require_once __DIR__ . '/../src/Domain/UserContext.php';
require_once __DIR__ . '/../src/Modules/AllModules.php';

use App\Domain\UserContext;
use App\Modules\AllModules\IamModule;
use App\Modules\AllModules\InspectionModule;
use App\Modules\AllModules\PolicyModule;
use App\Modules\AllModules\RiskScoringModule;
use App\Modules\AllModules\DecisionModule;

$user = new UserContext('alice@company.example', ['finance_manager'], 'Finance', 'BE', true, 'managed', 'Brussels');
$iam = (new IamModule())->authenticate($user);
$inspection = (new InspectionModule())->inspect('Analyse ce contrat pour John Doe. john.doe@example.com BE68539007547034 password=Secret123');
$policy = (new PolicyModule())->evaluate($user, $inspection, 'public_llm', ['GDPR', 'NIS2', 'ISO27001']);
$risk = (new RiskScoringModule())->score($user, $inspection);
$decision = (new DecisionModule())->decide($policy, $risk);
echo json_encode(['iam' => $iam, 'inspection' => $inspection, 'policy' => $policy, 'risk' => $risk, 'decision' => $decision], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . PHP_EOL;
