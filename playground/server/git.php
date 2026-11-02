<?php
/** Read-only Git import: fetch objects into a private temporary bare repository.
 * Never checkout files, execute hooks, recurse into submodules, or accept arbitrary
 * transports. Only configured Git hosts are contacted; credentials stay on server.
 */
declare(strict_types=1);
namespace SemanticRouter;
require_once __DIR__ . '/storage.php';

function repositoryUrl(mixed $input): string {
    if (!is_string($input) || strlen($input) > 500 || preg_match('/[\x00-\x20\x7f]/', $input)) throw new ApiError('Use an HTTPS or SSH repository URL.');
    $url = $input;
    if (preg_match('~^git@([a-zA-Z0-9.-]+):([a-zA-Z0-9_./-]+)$~D', $input, $match)) $url = 'ssh://git@' . $match[1] . '/' . $match[2];
    $parts = parse_url($url);
    if (!$parts || !in_array($parts['scheme'] ?? '', ['https', 'ssh'], true) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment']) || isset($parts['port'])) throw new ApiError('Use an HTTPS or SSH repository URL without credentials or a custom port.');
    if (isset($parts['user']) && (($parts['scheme'] ?? '') !== 'ssh' || $parts['user'] !== 'git')) throw new ApiError('Use git as the SSH user; keep credentials on the server.');
    $hosts = array_filter(array_map('trim', explode(',', getenv('SEMANTICROUTER_GIT_HOSTS') ?: 'github.com,gitlab.com,bitbucket.org')));
    if (!in_array(strtolower($parts['host'] ?? ''), $hosts, true)) throw new ApiError('This Git host is not enabled by the server administrator.');
    $path = trim($parts['path'] ?? '', '/');
    if (!preg_match('~^[a-zA-Z0-9_./-]+$~D', $path) || count(explode('/', $path)) < 2 || array_intersect(explode('/', $path), ['.', '..', ''])) throw new ApiError('Use a repository URL with an owner and repository name.');
    return $url;
}
function repositoryDirectory(mixed $value): string {
    if (!is_string($value) || strlen($value) > 250 || str_starts_with($value, '/') || str_contains($value, '\\') || preg_match('/[\x00-\x1f\x7f]/', $value)) throw new ApiError('Use a relative config directory.');
    $value = trim($value, '/');
    if ($value !== '' && array_intersect(explode('/', $value), ['.', '..', ''])) throw new ApiError('Use a config directory without traversal.');
    return $value;
}
function removeTemporaryRepository(string $root): void {
    if (!is_dir($root)) return;
    $files = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($files as $file) {
        if ($file->isLink() || !$file->isDir()) @unlink($file->getPathname()); else @rmdir($file->getPathname());
    }
    @rmdir($root);
}

/** Fixed argv avoids shell interpolation. Limits cover output, pack growth and
 * process time; stderr is retained only for server logs, not returned to clients. */
function gitProcess(array $args, string $root, int $limit = 1048576): string {
    if (!function_exists('proc_open')) throw new ApiError('Git sync requires proc_open on the server.', 503);
    $env = ['PATH' => getenv('PATH') ?: '/usr/bin:/bin', 'HOME' => getenv('HOME') ?: '/var/www', 'GIT_CONFIG_NOSYSTEM' => '1', 'GIT_CONFIG_GLOBAL' => '/dev/null', 'GIT_TERMINAL_PROMPT' => '0', 'GIT_ALLOW_PROTOCOL' => 'https:ssh', 'GIT_OPTIONAL_LOCKS' => '0', 'GIT_SSH_COMMAND' => 'ssh -oBatchMode=yes -oStrictHostKeyChecking=yes -oConnectTimeout=8'];
    $key = getenv('SEMANTICROUTER_GIT_SSH_KEY') ?: '';
    if ($key !== '') $env['GIT_SSH_COMMAND'] .= ' -i ' . escapeshellarg($key) . ' -oIdentitiesOnly=yes';
    $argv = ['git', '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never', '-c', 'protocol.https.allow=always', '-c', 'protocol.ssh.allow=always', '-c', 'http.followRedirects=false', '-c', 'submodule.recurse=false', ...$args];
    $process = proc_open($argv, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $root, $env, ['bypass_shell' => true]);
    if (!is_resource($process)) throw new ApiError('Git could not start.', 503);
    fclose($pipes[0]); stream_set_blocking($pipes[1], false); stream_set_blocking($pipes[2], false);
    $stdout = $stderr = ''; $start = microtime(true); $exit = -1; $failure = null;
    do {
        $stdout .= stream_get_contents($pipes[1]); $stderr .= stream_get_contents($pipes[2]);
        $status = proc_get_status($process);
        $packs = 0;
        foreach (glob($root . '/repo.git/objects/pack/*') ?: [] as $file) $packs += is_file($file) ? filesize($file) : 0;
        if (strlen($stdout) > $limit || strlen($stderr) > 1048576 || $packs > 100 * 1024 * 1024 || microtime(true) - $start > 25) {
            $failure = 'Repository exceeds the sync size or time limit.'; proc_terminate($process, 9); break;
        }
        if (!$status['running']) { $exit = $status['exitcode']; break; }
        usleep(20000);
    } while (true);
    $stdout .= stream_get_contents($pipes[1]); $stderr .= stream_get_contents($pipes[2]);
    fclose($pipes[1]); fclose($pipes[2]); $closed = proc_close($process);
    if ($failure) throw new ApiError($failure);
    if (($exit >= 0 ? $exit : $closed) !== 0) {
        error_log('SemanticRouter git: ' . substr($stderr, 0, 2000));
        throw new ApiError('Could not read the repository. Check the URL, branch and server deploy-key access.');
    }
    if (strlen($stdout) > $limit) throw new ApiError('Repository output exceeds the sync limit.');
    return $stdout;
}
function pullRepository(array $input): array {
    $url = repositoryUrl($input['url'] ?? '');
    $directory = repositoryDirectory($input['directory'] ?? '');
    $branch = $input['branch'] ?? 'HEAD';
    if (!is_string($branch) || !preg_match('~^[A-Za-z0-9_][A-Za-z0-9_./-]{0,150}$~D', $branch) || str_contains($branch, '..') || str_contains($branch, '//')) throw new ApiError('Use a branch name or commit id.');
    $lockRoot = sys_get_temp_dir() . '/semanticrouter-git-service-' . substr(hash('sha256', __DIR__), 0, 16);
    if (!is_dir($lockRoot) && !mkdir($lockRoot, 0700)) throw new ApiError('Git storage is unavailable.', 503);
    $lock = fopen($lockRoot . '/sync.lock', 'c');
    if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) throw new ApiError('Another sync is running. Try again shortly.', 503);
    chmod($lockRoot . '/sync.lock', 0600);
    $root = sys_get_temp_dir() . '/semanticrouter-git-' . identifier();
    if (!mkdir($root, 0700)) throw new ApiError('Git storage is unavailable.', 503);
    try {
        gitProcess(['init', '--bare', 'repo.git'], $root);
        $base = ['--git-dir=' . $root . '/repo.git'];
        gitProcess([...$base, 'fetch', '--depth=1', '--no-tags', '--no-recurse-submodules', '--', $url, $branch], $root);
        $commit = trim(gitProcess([...$base, 'rev-parse', '--verify', 'FETCH_HEAD^{commit}'], $root));
        if (!preg_match('/^[a-f0-9]{40,64}$/D', $commit)) throw new ApiError('Git did not return a commit.');
        $listing = gitProcess([...$base, 'ls-tree', '-r', '-z', '--long', $commit], $root, 4 * 1024 * 1024);
        $files = []; $total = 0; $names = [];
        foreach (explode("\0", $listing) as $line) {
            if ($line === '') continue;
            if (!preg_match('/^(100644|100755) blob ([a-f0-9]+) +([0-9]+)\t(.+)$/sD', $line, $match)) continue; // No symlinks or submodules.
            $path = $match[4];
            if ($directory !== '' && !str_starts_with($path, $directory . '/')) continue;
            if (array_filter(explode('/', $path), fn($part) => str_starts_with($part, '.'))) continue;
            if (!preg_match('/\.(cfg|rsc|txt)$/iD', $path)) continue;
            $name = pathinfo($path, PATHINFO_FILENAME);
            if (!preg_match('/^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/D', $name)) continue;
            if (isset($names[$name])) throw new ApiError('Config filenames must have unique device names.');
            $size = (int)$match[3]; $total += $size;
            if ($size > 5 * 1024 * 1024 || $total > 10 * 1024 * 1024 || count($files) >= 100) throw new ApiError('Choose at most 100 configs, under 5 MB each and 10 MB total.');
            $text = gitProcess([...$base, 'cat-file', 'blob', $match[2]], $root, 5 * 1024 * 1024);
            if (str_contains($text, "\0") || !preg_match('//u', $text)) throw new ApiError('Configs must be UTF-8 text.');
            $names[$name] = true; $files[] = ['name' => $name, 'path' => $path, 'text' => $text, 'sha256' => hash('sha256', $text)];
        }
        if (!$files) throw new ApiError('No .cfg, .rsc or .txt configs found in this directory.');
        return ['repository' => ['url' => $url, 'branch' => $branch, 'directory' => $directory, 'commit' => $commit], 'files' => $files];
    } finally { removeTemporaryRepository($root); flock($lock, LOCK_UN); fclose($lock); }
}
