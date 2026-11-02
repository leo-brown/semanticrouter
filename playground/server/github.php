<?php
/** GitHub OAuth identity only. Repository permissions are not requested and tokens
 * are discarded after profile verification. A read-only server deploy key handles
 * private config-repository pulls independently from account sign-in.
 */
declare(strict_types=1);
namespace SemanticRouter;
require_once __DIR__ . '/auth.php';

function callbackUrl(): string {
    $configured = getenv('SEMANTICROUTER_GITHUB_CALLBACK_URL') ?: '';
    if ($configured !== '') return $configured;
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    if (!preg_match('/^[a-zA-Z0-9.-]+(?::[0-9]+)?$/D', $host)) throw new ApiError('Configure a public callback URL.', 503);
    $local = preg_match('/^(localhost|127\.0\.0\.1)(:|$)/', $host);
    return ($local ? 'http://' : 'https://') . $host . rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? '/api.php'), '/') . '/oauth_callback.php';
}
function githubConfiguration(Store $store): array {
    $saved = $store->setting('github') ?? [];
    return ['client_id' => getenv('SEMANTICROUTER_GITHUB_CLIENT_ID') ?: ($saved['client_id'] ?? ''), 'client_secret' => getenv('SEMANTICROUTER_GITHUB_CLIENT_SECRET') ?: ($saved['client_secret'] ?? ''), 'callback_url' => getenv('SEMANTICROUTER_GITHUB_CALLBACK_URL') ?: ($saved['callback_url'] ?? callbackUrl())];
}
function configureGithub(Store $store, array $input): void {
    if (!canBootstrap()) throw new ApiError('Only the installation administrator can configure GitHub login.', 403);
    $id = $input['client_id'] ?? ''; $secret = $input['client_secret'] ?? ''; $callback = $input['callback_url'] ?? callbackUrl();
    $url = is_string($callback) ? parse_url($callback) : false;
    if (!is_string($id) || !preg_match('/^[A-Za-z0-9._-]{10,100}$/D', $id) || !is_string($secret) || strlen($secret) < 20 || strlen($secret) > 200 || !$url || !in_array($url['scheme'] ?? '', ['http','https'], true) || isset($url['user']) || isset($url['query']) || isset($url['fragment']) || !str_ends_with($url['path'] ?? '', '/oauth_callback.php')) throw new ApiError('Enter the OAuth Client ID, Client Secret and exact callback URL.');
    if ($url['scheme'] !== 'https' && !in_array($url['host'] ?? '', ['localhost','127.0.0.1'], true)) throw new ApiError('The callback must use HTTPS.');
    $store->saveSetting('github', ['client_id' => $id, 'client_secret' => $secret, 'callback_url' => $callback]);
}
function oauthStart(Store $store, ?string $invite = null): string {
    sessionStart(); $config = githubConfiguration($store);
    if ($config['client_id'] === '' || $config['client_secret'] === '') throw new ApiError('GitHub sign-in needs an OAuth app. Ask the installation administrator to complete GitHub setup.', 503);
    if ($invite !== null && !preg_match('/^[a-f0-9]{64}$/D', $invite)) throw new ApiError('Invalid invitation.');
    $state = bin2hex(random_bytes(32));
    $verifier = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    $_SESSION['github_oauth'] = ['state' => $state, 'verifier' => $verifier, 'expires' => time() + 600, 'invite' => $invite];
    $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    return 'https://github.com/login/oauth/authorize?' . http_build_query(['client_id' => $config['client_id'], 'redirect_uri' => $config['callback_url'], 'state' => $state, 'scope' => 'read:user', 'code_challenge' => $challenge, 'code_challenge_method' => 'S256', 'prompt' => 'select_account']);
}
/** Consume before network exchange so a callback cannot be replayed. */
function consumeOauthState(mixed $state): array {
    sessionStart(); $flow = $_SESSION['github_oauth'] ?? null; unset($_SESSION['github_oauth']);
    if (!$flow || $flow['expires'] < time() || !is_string($state) || !hash_equals($flow['state'], $state)) throw new ApiError('Sign-in expired or could not be verified. Start again.', 400);
    return $flow;
}
final class Github {
    /** Optional transport is used by deterministic tests; URLs are fixed constants. */
    public function __construct(private array $config, private mixed $transport = null) {}
    private function request(string $method, string $url, array $headers = [], ?array $body = null): array {
        if ($this->transport) return ($this->transport)($method, $url, $headers, $body);
        if (!function_exists('curl_init')) throw new ApiError('GitHub sign-in requires PHP cURL.', 503);
        $curl = curl_init($url); $response = '';
        curl_setopt_array($curl, [CURLOPT_CUSTOMREQUEST => $method, CURLOPT_HTTPHEADER => ['Accept: application/json', 'User-Agent: SemanticRouter', ...$headers], CURLOPT_FOLLOWLOCATION => false, CURLOPT_CONNECTTIMEOUT => 5, CURLOPT_TIMEOUT => 15, CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2, CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk) use (&$response): int { if (strlen($response) + strlen($chunk) > 1048576) return 0; $response .= $chunk; return strlen($chunk); }]);
        if ($body !== null) curl_setopt($curl, CURLOPT_POSTFIELDS, http_build_query($body));
        $ok = curl_exec($curl); $status = curl_getinfo($curl, CURLINFO_RESPONSE_CODE); curl_close($curl);
        if ($ok === false || $status !== 200) throw new ApiError('GitHub could not verify this request. Try again.', 502);
        $value = json_decode($response, true, 32, JSON_THROW_ON_ERROR);
        if (!is_array($value) || isset($value['error'])) throw new ApiError('GitHub did not authorize sign-in.', 401);
        return $value;
    }
    public function profile(string $code, string $verifier): array {
        if ($code === '' || strlen($code) > 500) throw new ApiError('Missing GitHub authorization code.');
        $token = $this->request('POST', 'https://github.com/login/oauth/access_token', [], ['client_id' => $this->config['client_id'], 'client_secret' => $this->config['client_secret'], 'redirect_uri' => $this->config['callback_url'], 'code' => $code, 'code_verifier' => $verifier]);
        $access = $token['access_token'] ?? '';
        if (!is_string($access) || !preg_match('/^[A-Za-z0-9_]+$/D', $access)) throw new ApiError('GitHub did not return a valid access token.', 401);
        // Always revalidate /user, even if this browser signed in before.
        $profile = $this->request('GET', 'https://api.github.com/user', ['Authorization: Bearer ' . $access]);
        return ['id' => $profile['id'] ?? null, 'login' => githubLogin($profile['login'] ?? '')];
    }
    public function lookup(string $login): array {
        $profile = $this->request('GET', 'https://api.github.com/users/' . rawurlencode(githubLogin($login)));
        if (!isset($profile['id'])) throw new ApiError('GitHub user not found.');
        return ['id' => $profile['id'], 'login' => githubLogin($profile['login'] ?? '')];
    }
}
