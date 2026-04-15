<?php
declare(strict_types=1);

use App\Application\ProcessGatewayRequest;
use App\Controller\ConnectorsController;
use App\Controller\DashboardController;
use App\Controller\GatewayController;
use App\Controller\RagController;
use App\Infrastructure\AuditLogger;
use App\Infrastructure\JsonStore;
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

require_once __DIR__ . '/../src/Support/helpers.php';
require_once __DIR__ . '/../src/Infrastructure/JsonStore.php';
require_once __DIR__ . '/../src/Infrastructure/AuditLogger.php';
require_once __DIR__ . '/../src/Infrastructure/LlmConnector.php';
require_once __DIR__ . '/../src/Domain/UserContext.php';
require_once __DIR__ . '/../src/Domain/GatewayRequest.php';
require_once __DIR__ . '/../src/Modules/AllModules.php';
require_once __DIR__ . '/../src/Application/ProcessGatewayRequest.php';
require_once __DIR__ . '/../src/Controller/Controllers.php';

$config = require __DIR__ . '/../config/config.php';

$gatewayController = new GatewayController(
    new ProcessGatewayRequest(
        new IamModule(),
        new InspectionModule(),
        new MaskingModule(new JsonStore($config['storage']['vault'])),
        new PolicyModule(),
        new RiskScoringModule(),
        new DecisionModule(),
        new RoutingModule($config['routing']),
        new RagModule(new JsonStore($config['storage']['rag'])),
        new ResponseFilteringModule(),
        new AuditComplianceModule(new AuditLogger($config['storage']['audit'])),
        new DashboardModule(new JsonStore($config['storage']['dashboard'])),
        new ConnectorsModule($config['connectors']),
        new LlmConnector($config['llm']['endpoint'], $config['llm']['api_key'])
    )
);

$dashboardController = new DashboardController(new DashboardModule(new JsonStore($config['storage']['dashboard'])));
$connectorsController = new ConnectorsController(new ConnectorsModule($config['connectors']));
$ragController = new RagController(new RagModule(new JsonStore($config['storage']['rag'])));

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

if ($method === 'GET' && $path === '/') {
    header('Content-Type: text/html; charset=utf-8');
    echo '<!doctype html><html><head><meta charset="utf-8"><title>AI Secure Gateway</title></head><body>';
    echo '<h1>AI Secure Gateway</h1><ul><li>POST /gateway/process</li><li>GET /dashboard/summary</li><li>GET /connectors</li><li>POST /rag/query</li></ul>';
    exit;
}
if ($method === 'POST' && $path === '/gateway/process') { $gatewayController->process(); }
if ($method === 'GET' && $path === '/dashboard/summary') { $dashboardController->summary(); }
if ($method === 'GET' && $path === '/connectors') { $connectorsController->list(); }
if ($method === 'POST' && $path === '/rag/query') { $ragController->query(); }
jsonResponse(['error' => 'not_found', 'message' => 'Route inconnue'], 404);
