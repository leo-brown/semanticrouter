<?php
/** Serve one build-selected original solely for an authenticated export request.
 * The guarded snapshot fixes original bytes and hashes. No caller-supplied path is
 * read, and later collector updates cannot change the input beneath an existing model.
 */
declare(strict_types=1);
require_once dirname(__DIR__) . '/auth.php';
requireVisualiserAuth();
header('Content-Type: text/plain; charset=UTF-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

$manifest = json_decode(base64_decode('__SOURCE_MANIFEST__'), true, 512, JSON_THROW_ON_ERROR);
$device = $_GET['device'] ?? '';
$expected = $_GET['hash'] ?? '';
if (!is_string($device) || !is_string($expected) || !isset($manifest[$device])) {
    http_response_code(404);
    exit('Source not available for this device.');
}
$entry = $manifest[$device];
if (!hash_equals($entry['sha256'], $expected)) {
    http_response_code(409);
    exit('The source does not match this workspace. Load its original export.');
}
// This immutable original is the same input used to build the semantic model.
$content = base64_decode($entry['content'], true);
if ($content === false || !hash_equals($entry['sha256'], hash('sha256', $content))) {
    http_response_code(409);
    exit('Original snapshot integrity check failed. Rebuild this workspace.');
}
echo $content;
