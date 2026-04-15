<?php
declare(strict_types=1);
namespace App\Controller;

use App\Application\ProcessGatewayRequest;
use App\Domain\UserContext;
use App\Modules\AllModules\ConnectorsModule;
use App\Modules\AllModules\DashboardModule;
use App\Modules\AllModules\RagModule;

final class GatewayController {
    public function __construct(private readonly ProcessGatewayRequest $useCase) {}
    public function process(): never {
        $payload = json_decode(file_get_contents('php://input') ?: '', true);
        if (!is_array($payload)) \jsonResponse(['error' => 'invalid_json', 'message' => 'Le body doit être un JSON valide.'], 422);
        try { \jsonResponse($this->useCase->execute($payload), 200); } catch (\Throwable $e) { \jsonResponse(['error' => 'processing_failed', 'message' => $e->getMessage()], 400); }
    }
}
final class DashboardController {
    public function __construct(private readonly DashboardModule $dashboard) {}
    public function summary(): never { \jsonResponse($this->dashboard->summary(), 200); }
}
final class ConnectorsController {
    public function __construct(private readonly ConnectorsModule $connectors) {}
    public function list(): never { \jsonResponse($this->connectors->list(), 200); }
}
final class RagController {
    public function __construct(private readonly RagModule $rag) {}
    public function query(): never {
        $payload = json_decode(file_get_contents('php://input') ?: '', true);
        if (!is_array($payload)) \jsonResponse(['error' => 'invalid_json', 'message' => 'Le body doit être un JSON valide.'], 422);
        $user = UserContext::fromArray($payload['user'] ?? []); $documentIds = array_values($payload['document_ids'] ?? []);
        \jsonResponse($this->rag->query($user, $documentIds), 200);
    }
}
