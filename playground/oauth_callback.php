<?php
/** OAuth callback verifies state/PKCE and identity before creating a local session.
 * The GitHub access token is never returned to JavaScript or saved in a workspace.
 */
declare(strict_types=1);
require_once __DIR__ . '/server/github.php';
header('Cache-Control: no-store');
header('Referrer-Policy: no-referrer');
try {
    $flow = SemanticRouter\consumeOauthState($_GET['state'] ?? null);
    if (isset($_GET['error'])) throw new SemanticRouter\ApiError('GitHub sign-in was cancelled.');
    $store = SemanticRouter\database();
    $github = new SemanticRouter\Github(SemanticRouter\githubConfiguration($store));
    $user = $store->githubAccount($github->profile((string)($_GET['code'] ?? ''), $flow['verifier']));
    if ($flow['invite']) $store->acceptGithub($user['id'], $flow['invite']);
    SemanticRouter\authenticate($user);
    header('Location: ./');
} catch (Throwable $error) {
    $_SESSION['oauth_error'] = $error instanceof SemanticRouter\ApiError ? $error->getMessage() : 'GitHub sign-in could not complete. Try again.';
    header('Location: login.php');
}
