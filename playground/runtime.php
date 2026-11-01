<?php

declare(strict_types=1);

// Explicit MIME types make the worker portable to nginx installations whose
// mime.types does not include .mjs. Only official runtime assets may be read.
require_once dirname(__DIR__) . '/auth.php';
requireVisualiserAuth();

$types = [
    'pyodide.mjs' => 'application/javascript',
    'pyodide.asm.mjs' => 'application/javascript',
    'pyodide.asm.wasm' => 'application/wasm',
    'python_stdlib.zip' => 'application/zip',
    'pyodide-lock.json' => 'application/json',
];
// A leading slash is part of the runtime base URL, not a filesystem path.
// The exact allowlist, rather than path normalization, prevents traversal.
$requested = $_GET['file'] ?? '';
$name = is_string($requested) ? ltrim($requested, '/') : '';
if (!isset($types[$name])) {
    http_response_code(404);
    exit;
}
$path = __DIR__ . '/runtime/' . $name;
if (!is_file($path) || !is_readable($path)) {
    http_response_code(404);
    exit;
}
// ES module imports and streaming WebAssembly compilation require these MIME types.
// Cache only in the authenticated browser; shared caches must not retain responses.
header('Content-Type: ' . $types[$name]);
header('X-Content-Type-Options: nosniff');
header('Cache-Control: private, max-age=86400');
header('Content-Length: ' . filesize($path));
// HEAD is used by deployment diagnostics and must return headers without the binary body.
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'HEAD') {
    readfile($path);
}
