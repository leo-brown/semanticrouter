<?php
/** Session and deployment configuration shared by entry points and runtime assets.
 * Team authentication never authorizes the BF data/source endpoints. Those retain
 * their existing independent Visualiser guard.
 */
declare(strict_types=1);
namespace SemanticRouter;
require_once __DIR__ . '/storage.php';

function integrateVisualiser(): void {
    if (getenv('SEMANTICROUTER_STANDALONE') === '1') return;
    $path = dirname(__DIR__, 2) . '/auth.php';
    if (is_file($path)) require_once $path;
}
function canBootstrap(): bool {
    integrateVisualiser();
    if (function_exists('visualiserAuthValid')) return \visualiserAuthValid();
    $configured = getenv('SEMANTICROUTER_SETUP_TOKEN') ?: '';
    $supplied = $_SERVER['HTTP_X_SEMANTICROUTER_SETUP'] ?? '';
    return $configured !== '' && is_string($supplied) && hash_equals($configured, $supplied);
}
function sessionStart(): void {
    if (session_status() === PHP_SESSION_ACTIVE) return;
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    session_name('semanticrouter_session');
    $path = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/')), '/') . '/';
    session_set_cookie_params(['lifetime' => 43200, 'path' => $path, 'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off', 'httponly' => true, 'samesite' => 'Lax']);
    session_start();
    if (isset($_SESSION['last_seen']) && (int)$_SESSION['last_seen'] < time() - 43200) { $_SESSION = []; session_regenerate_id(true); }
    $_SESSION['last_seen'] = time();
    $_SESSION['csrf'] ??= bin2hex(random_bytes(32));
}
function teamSessionValid(): bool { sessionStart(); return isset($_SESSION['user_id']) && is_string($_SESSION['user_id']); }
function csrf(): string { sessionStart(); $_SESSION['csrf'] ??= bin2hex(random_bytes(32)); return $_SESSION['csrf']; }
function requireCsrf(): void {
    $token = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!is_string($token) || !hash_equals(csrf(), $token)) throw new ApiError('Refresh the page and try again.', 403);
}
function authenticate(array $user): void {
    sessionStart(); session_regenerate_id(true);
    $_SESSION['user_id'] = $user['id']; $_SESSION['csrf'] = bin2hex(random_bytes(32));
}
function requireUser(Store $store): array {
    if (!teamSessionValid()) throw new ApiError('Sign in to your team first.', 401);
    return $store->user($_SESSION['user_id']);
}
function database(): Store {
    integrateVisualiser();
    $dsn = getenv('SEMANTICROUTER_DB_DSN') ?: '';
    $user = getenv('SEMANTICROUTER_DB_USER') ?: '';
    $password = getenv('SEMANTICROUTER_DB_PASSWORD') ?: '';
    // A supplied DSN is authoritative. Do not silently switch databases if it fails.
    if ($dsn === '') {
        $directory = getenv('SEMANTICROUTER_DATA_DIR') ?: '/var/tmp/semanticrouter-' . substr(hash('sha256', dirname(__DIR__)), 0, 16);
        $web = realpath($_SERVER['DOCUMENT_ROOT'] ?? '') ?: '';
        $parent = realpath(dirname($directory));
        if (!$parent || ($web !== '' && ($parent === $web || str_starts_with($parent, $web . DIRECTORY_SEPARATOR)))) throw new ApiError('Configure private team storage outside the web root.', 503);
        if (is_link($directory) || (!is_dir($directory) && !mkdir($directory, 0700))) throw new ApiError('Private team storage could not be created.', 503);
        if (function_exists('posix_geteuid') && fileowner($directory) !== posix_geteuid()) throw new ApiError('Private team storage has the wrong owner.', 503);
        chmod($directory, 0700);
        $path = $directory . '/workspaces.sqlite';
        if (is_link($path)) throw new ApiError('Invalid team database path.', 503);
        $dsn = 'sqlite:' . $path;
    }
    if (str_starts_with($dsn, 'sqlite:')) {
        $path = substr($dsn, 7);
        $root = realpath($_SERVER['DOCUMENT_ROOT'] ?? '') ?: '';
        $parent = realpath(dirname($path));
        if (!$parent || ($root !== '' && ($parent === $root || str_starts_with($parent, $root . DIRECTORY_SEPARATOR)))) throw new ApiError('SQLite storage must be outside the web root.', 503);
    }
    $store = new Store(new \PDO($dsn, $user, $password));
    if (str_starts_with($dsn, 'sqlite:') && is_file(substr($dsn, 7))) chmod(substr($dsn, 7), 0600);
    return $store;
}
