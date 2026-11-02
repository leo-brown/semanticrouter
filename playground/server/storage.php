<?php
/** Isolated team/workspace persistence. PDO parameters carry every user value.
 * MySQL can reuse an existing host installation; standalone installs can select
 * SQLite outside the web root. No router configs are written into public files.
 */
declare(strict_types=1);
namespace SemanticRouter;

final class ApiError extends \RuntimeException {
    public function __construct(string $message, public int $status = 400) { parent::__construct($message); }
}
function identifier(): string { return bin2hex(random_bytes(16)); }
function label(mixed $value): string {
    $name = trim(is_string($value) ? $value : '');
    if ($name === '' || strlen($name) > 200) throw new ApiError('Use a name between 1 and 200 bytes.');
    return $name;
}
function githubLogin(mixed $value): string {
    $login = strtolower(trim(is_string($value) ? $value : ''));
    if (!preg_match('/^[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?$/D', $login)) throw new ApiError('Enter a GitHub username.');
    return $login;
}

final class Store {
    public function __construct(public \PDO $db) {
        $db->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
        $db->setAttribute(\PDO::ATTR_DEFAULT_FETCH_MODE, \PDO::FETCH_ASSOC);
        $driver = $db->getAttribute(\PDO::ATTR_DRIVER_NAME);
        if ($driver === 'sqlite') $db->exec('PRAGMA busy_timeout=5000');
        if (!in_array($driver, ['sqlite', 'mysql'], true)) throw new ApiError('Use a configured SQLite or MySQL database.', 503);
        foreach ([
            'accounts (id VARCHAR(64) PRIMARY KEY, github_id VARCHAR(32) NOT NULL UNIQUE, github_login VARCHAR(39) NOT NULL, created_at BIGINT NOT NULL)',
            'teams (id VARCHAR(64) PRIMARY KEY, name VARCHAR(200) NOT NULL, created_by VARCHAR(64) NOT NULL, created_at BIGINT NOT NULL)',
            'members (team_id VARCHAR(64) NOT NULL, user_id VARCHAR(64) NOT NULL, role VARCHAR(16) NOT NULL, PRIMARY KEY (team_id, user_id))',
            'invites (token_hash VARCHAR(64) PRIMARY KEY, team_id VARCHAR(64) NOT NULL, github_id VARCHAR(32) NOT NULL, github_login VARCHAR(39) NOT NULL, expires_at BIGINT NOT NULL, used_at BIGINT NULL)',
            'workspaces (id VARCHAR(64) PRIMARY KEY, team_id VARCHAR(64) NOT NULL, name VARCHAR(200) NOT NULL, snapshot LONGTEXT NOT NULL, revision BIGINT NOT NULL, updated_at BIGINT NOT NULL, updated_by VARCHAR(64) NOT NULL)',
            'settings (name VARCHAR(64) PRIMARY KEY, value LONGTEXT NOT NULL)',
        ] as $table) $db->exec('CREATE TABLE IF NOT EXISTS semanticrouter_' . $table . ($driver === 'mysql' ? ' ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci' : ''));
    }
    public function query(string $sql, array $params = []): \PDOStatement {
        $query = $this->db->prepare($sql); $query->execute($params); return $query;
    }
    public function user(string $id): array {
        $user = $this->query('SELECT id,github_id,github_login FROM semanticrouter_accounts WHERE id=?', [$id])->fetch();
        if (!$user) throw new ApiError('Sign in to continue.', 401);
        return $user;
    }
    public function membership(string $user, string $team, bool $owner = false): array {
        $row = $this->query('SELECT role FROM semanticrouter_members WHERE team_id=? AND user_id=?', [$team, $user])->fetch();
        if (!$row || ($owner && $row['role'] !== 'owner')) throw new ApiError('This team is not available to your account.', 403);
        return $row;
    }
    public function teams(string $user): array {
        return $this->query('SELECT t.id,t.name,m.role FROM semanticrouter_teams t JOIN semanticrouter_members m ON t.id=m.team_id WHERE m.user_id=? ORDER BY t.name', [$user])->fetchAll();
    }
    public function createTeam(string $user, mixed $name): array {
        $id = identifier(); $name = label($name);
        $this->db->beginTransaction();
        try {
            $this->query('INSERT INTO semanticrouter_teams (id,name,created_by,created_at) VALUES (?,?,?,?)', [$id, $name, $user, time()]);
            $this->query('INSERT INTO semanticrouter_members (team_id,user_id,role) VALUES (?,?,?)', [$id, $user, 'owner']);
            $this->db->commit();
        } catch (\Throwable $error) { $this->db->rollBack(); throw $error; }
        return ['id' => $id, 'name' => $name, 'role' => 'owner'];
    }
    /** GitHub's numeric id is stable even when a user renames their account. */
    public function githubAccount(array $profile): array {
        $githubId = (string)($profile['id'] ?? ''); $login = githubLogin($profile['login'] ?? '');
        if (!preg_match('/^[1-9][0-9]{0,20}$/D', $githubId)) throw new ApiError('GitHub returned an invalid identity.');
        $row = $this->query('SELECT id FROM semanticrouter_accounts WHERE github_id=?', [$githubId])->fetch();
        if ($row) {
            $id = $row['id'];
            $this->query('UPDATE semanticrouter_accounts SET github_login=? WHERE id=?', [$login, $id]);
        } else {
            $id = identifier();
            $this->query('INSERT INTO semanticrouter_accounts (id,github_id,github_login,created_at) VALUES (?,?,?,?)', [$id, $githubId, $login, time()]);
        }
        return $this->user($id);
    }
    public function setting(string $name): ?array {
        $row = $this->query('SELECT value FROM semanticrouter_settings WHERE name=?', [$name])->fetch();
        return $row ? json_decode($row['value'], true, 512, JSON_THROW_ON_ERROR) : null;
    }
    public function saveSetting(string $name, array $value): void {
        $this->db->beginTransaction();
        try {
            $this->query('DELETE FROM semanticrouter_settings WHERE name=?', [$name]);
            $this->query('INSERT INTO semanticrouter_settings (name,value) VALUES (?,?)', [$name, json_encode($value, JSON_THROW_ON_ERROR)]);
            $this->db->commit();
        } catch (\Throwable $error) { $this->db->rollBack(); throw $error; }
    }
    public function invite(string $user, string $team, array $profile): string {
        $this->membership($user, $team, true);
        $githubId = (string)$profile['id']; $login = githubLogin($profile['login']);
        if (!preg_match('/^[1-9][0-9]{0,20}$/D', $githubId)) throw new ApiError('Invalid GitHub identity.');
        $token = bin2hex(random_bytes(32));
        $this->query('INSERT INTO semanticrouter_invites (token_hash,team_id,github_id,github_login,expires_at,used_at) VALUES (?,?,?,?,?,NULL)', [hash('sha256', $token), $team, $githubId, $login, time() + 604800]);
        return $token;
    }
    /** Membership is granted only to the invited GitHub id, not a mutable username. */
    public function acceptGithub(string $userId, string $token): void {
        $user = $this->user($userId);
        if (!preg_match('/^[a-f0-9]{64}$/D', $token)) throw new ApiError('Invitation is invalid or expired.');
        $tokenHash = hash('sha256', $token);
        $invite = $this->query('SELECT * FROM semanticrouter_invites WHERE token_hash=? AND used_at IS NULL', [$tokenHash])->fetch();
        if (!$invite || (int)$invite['expires_at'] < time() || !hash_equals($invite['github_id'], $user['github_id'])) throw new ApiError('Invitation is invalid, expired, or belongs to another GitHub account.');
        $this->db->beginTransaction();
        try {
            $used = $this->query('UPDATE semanticrouter_invites SET used_at=? WHERE token_hash=? AND used_at IS NULL AND expires_at>=?', [time(), $tokenHash, time()]);
            if ($used->rowCount() !== 1) throw new ApiError('Invitation is invalid or expired.');
            if (!$this->query('SELECT role FROM semanticrouter_members WHERE team_id=? AND user_id=?', [$invite['team_id'], $userId])->fetch()) $this->query('INSERT INTO semanticrouter_members (team_id,user_id,role) VALUES (?,?,?)', [$invite['team_id'], $userId, 'member']);
            $this->db->commit();
        } catch (\Throwable $error) { $this->db->rollBack(); throw $error; }
    }
    public function workspaces(string $user, string $team): array {
        $this->membership($user, $team);
        return $this->query('SELECT id,name,revision,updated_at FROM semanticrouter_workspaces WHERE team_id=? ORDER BY name', [$team])->fetchAll();
    }
    public function workspace(string $user, string $team, string $id): array {
        $this->membership($user, $team);
        $row = $this->query('SELECT id,name,revision,updated_at,snapshot FROM semanticrouter_workspaces WHERE id=? AND team_id=?', [$id, $team])->fetch();
        if (!$row) throw new ApiError('Workspace not found.', 404);
        $row['snapshot'] = json_decode($row['snapshot'], true, 512, JSON_THROW_ON_ERROR);
        $row['revision'] = (int)$row['revision']; return $row;
    }
    /** A compare-and-swap revision prevents one teammate silently replacing another. */
    public function saveWorkspace(string $user, string $team, array $input): array {
        $this->membership($user, $team); $name = label($input['name'] ?? null);
        $id = (string)($input['id'] ?? identifier());
        if (!preg_match('/^[a-f0-9]{32}$/D', $id)) throw new ApiError('Invalid workspace id.');
        $snapshot = $input['snapshot'] ?? null;
        if (!is_array($snapshot) || !isset($snapshot['routers']) || !is_array($snapshot['routers']) || !is_array($snapshot['rules'] ?? [])) throw new ApiError('Workspace needs router and rule arrays.');
        $encoded = json_encode($snapshot, JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE);
        if (strlen($encoded) > 10 * 1024 * 1024) throw new ApiError('Workspace exceeds 10 MB.');
        $revision = $input['revision'] ?? 0;
        if (!is_int($revision) || $revision < 0) throw new ApiError('Invalid workspace revision.');
        if ($revision === 0) {
            // Globally unique ids also prevent moving an existing workspace to a new team.
            if ($this->query('SELECT id FROM semanticrouter_workspaces WHERE id=?', [$id])->fetch()) throw new ApiError('Workspace changed. Open its latest version before saving.', 409);
            $this->query('INSERT INTO semanticrouter_workspaces (id,team_id,name,snapshot,revision,updated_at,updated_by) VALUES (?,?,?,?,?,?,?)', [$id, $team, $name, $encoded, 1, time(), $user]);
        } else {
            $updated = $this->query('UPDATE semanticrouter_workspaces SET name=?,snapshot=?,revision=revision+1,updated_at=?,updated_by=? WHERE id=? AND team_id=? AND revision=?', [$name, $encoded, time(), $user, $id, $team, $revision]);
            if ($updated->rowCount() !== 1) throw new ApiError('Workspace changed. Open its latest version before saving.', 409);
        }
        return $this->workspace($user, $team, $id);
    }
}
