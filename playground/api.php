<?php
/** JSON-only team API. Read access and every workspace write are membership-scoped.
 * POSTs need a session CSRF token, including login and invitation acceptance.
 */
declare(strict_types=1);
require_once __DIR__ . '/server/auth.php';
require_once __DIR__ . '/server/git.php';
require_once __DIR__ . '/server/github.php';
use SemanticRouter\ApiError;
use function SemanticRouter\{authenticate,canBootstrap,csrf,database,identifier,requireCsrf,requireUser,sessionStart,teamSessionValid};
header('Content-Type: application/json');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
try {
    sessionStart();
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    if (!in_array($method, ['GET', 'POST'], true)) throw new ApiError('Method not allowed.', 405);
    $input = [];
    if ($method === 'POST') {
        requireCsrf();
        if (!str_starts_with(strtolower($_SERVER['CONTENT_TYPE'] ?? ''), 'application/json')) throw new ApiError('Send JSON requests.', 415);
        $raw = file_get_contents('php://input', false, null, 0, 11 * 1024 * 1024);
        if (strlen($raw) > 10 * 1024 * 1024) throw new ApiError('Request exceeds 10 MB.', 413);
        $input = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($input)) throw new ApiError('Request must be an object.');
    }
    $action = (string)($input['action'] ?? $_GET['action'] ?? 'session');
    $read = in_array($action, ['session', 'bootstrap', 'workspaces', 'workspace'], true);
    if (($method === 'GET') !== $read) throw new ApiError('Method not allowed.', 405);
    // The public session endpoint stays usable even before a database is configured.
    $store = null; $storageAvailable = true; $storageDiagnostic = null;
    try { $store = database(); } catch (Throwable $error) {
        if ($action !== 'session') throw $error;
        $storageAvailable = false;
        $storageDiagnostic = ['type' => get_class($error), 'code' => $error->getCode(), 'driver_code' => $error instanceof PDOException ? ($error->errorInfo[1] ?? null) : null, 'drivers' => class_exists('PDO') ? PDO::getAvailableDrivers() : []];
    }
    if ($action === 'session') {
        $user = teamSessionValid() && $store ? requireUser($store) : null;
        $response = ['user' => $user, 'csrf' => csrf(), 'can_bootstrap' => canBootstrap(), 'storage_available' => $storageAvailable, 'teams' => $user ? $store->teams($user['id']) : [], 'github_configured' => $store ? SemanticRouter\githubConfiguration($store)['client_id'] !== '' && SemanticRouter\githubConfiguration($store)['client_secret'] !== '' : false, 'callback_url' => SemanticRouter\callbackUrl()];
        if (!$storageAvailable && canBootstrap()) $response['storage_diagnostic'] = $storageDiagnostic;
    } elseif ($action === 'oauth_start') {
        $response = ['url' => SemanticRouter\oauthStart($store, isset($input['invite']) ? (string)$input['invite'] : null)];
    } elseif ($action === 'configure_github') {
        SemanticRouter\configureGithub($store, $input); $response = ['configured' => true];
    } else {
        $user = requireUser($store); $team = (string)($input['team_id'] ?? $_GET['team_id'] ?? '');
        switch ($action) {
            case 'logout': $_SESSION = []; session_regenerate_id(true); $response = ['csrf' => csrf()]; break;
            case 'create_team': $response = ['team' => $store->createTeam($user['id'], $input['name'] ?? '')]; break;
            case 'invite':
                $store->membership($user['id'], $team, true);
                $github = new SemanticRouter\Github(SemanticRouter\githubConfiguration($store));
                $response = ['token' => $store->invite($user['id'], $team, $github->lookup((string)($input['github_login'] ?? '')))]; break;
            case 'workspaces': $response = ['workspaces' => $store->workspaces($user['id'], $team)]; break;
            case 'workspace': $response = ['workspace' => $store->workspace($user['id'], $team, (string)($_GET['id'] ?? ''))]; break;
            case 'save_workspace': $response = ['workspace' => $store->saveWorkspace($user['id'], $team, $input)]; break;
            case 'bootstrap':
                // Team entry starts empty. BF data.php remains protected separately.
                $response = ['routers' => [], 'rules' => [], 'policy' => new stdClass(), 'findings' => [], 'sources' => new stdClass(), 'workspace_namespace' => 'user-' . $user['id'], 'workspace_id' => 'personal-' . $user['id'], 'workspace_name' => 'New workspace', 'mode' => 'Team workspace']; break;
            case 'git_pull':
                $store->membership($user['id'], $team);
                session_write_close();
                $response = SemanticRouter\pullRepository($input); break;
            default: throw new ApiError('Unknown operation.', 404);
        }
    }
    echo json_encode(['ok' => true, ...$response], JSON_THROW_ON_ERROR);
} catch (ApiError $error) {
    http_response_code($error->status); echo json_encode(['ok' => false, 'error' => $error->getMessage()]);
} catch (JsonException $error) {
    http_response_code(400); echo json_encode(['ok' => false, 'error' => 'Invalid JSON request.']);
} catch (Throwable $error) {
    error_log('SemanticRouter service: ' . $error->getMessage());
    http_response_code(503); echo json_encode(['ok' => false, 'error' => 'Team service unavailable. Check the server storage configuration.']);
}
