<?php
/** Public account entry. It serves no BF models, config files or access credentials. */
declare(strict_types=1);
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
require_once __DIR__ . '/server/auth.php';
SemanticRouter\sessionStart();
?><!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SemanticRouter · Team login</title><link rel="stylesheet" href="style.css"><link rel="stylesheet" href="ide.css"></head>
<body data-team-api="api.php" class="login-page"><main class="login-card"><a class="brand" href="./">⤨ SemanticRouter</a><h1>Sign in to your team</h1><p>Shared config workspaces and reusable network tests.</p><button id="login-submit" class="button primary" disabled>Sign in with GitHub</button><div id="github-setup"></div><p id="login-error" class="error-text" role="status"><?php echo htmlspecialchars((string)($_SESSION['oauth_error'] ?? ''), ENT_QUOTES, 'UTF-8'); unset($_SESSION['oauth_error']); ?></p><p class="helper">Team membership is granted by invitation. New accounts start with an empty workspace.</p><a href="./" class="text-button">Back to workbench</a></main><script type="module" src="login.js"></script></body></html>
