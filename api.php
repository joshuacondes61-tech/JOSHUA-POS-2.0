<?php
declare(strict_types=1);

/*
 * JOSHUA POS API
 * Database credentials are read only from Wasmer's DB_* environment variables.
 * Set POS_ALLOWED_ORIGIN to https://joshuacondes61-tech.github.io in Wasmer.
 */
$allowedOrigin = getenv('POS_ALLOWED_ORIGIN') ?: 'https://joshuacondes61-tech.github.io';
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if ($origin !== '' && hash_equals($allowedOrigin, $origin)) {
    header('Access-Control-Allow-Origin: ' . $allowedOrigin);
    header('Vary: Origin');
    header('Access-Control-Allow-Methods: GET, POST, PUT, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Authorization');
    header('Access-Control-Max-Age: 86400');
}
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

function respond(int $status, array $data): never {
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}
function db(): PDO {
    static $pdo = null;
    if ($pdo instanceof PDO) return $pdo;
    $host = getenv('DB_HOST') ?: '';
    $name = getenv('DB_NAME') ?: '';
    $user = getenv('DB_USERNAME') ?: '';
    $pass = getenv('DB_PASSWORD') ?: '';
    $port = getenv('DB_PORT') ?: '';
    if ($host === '' || $name === '' || $user === '' || $port === '') {
        throw new RuntimeException('Wasmer database environment variables are not configured.');
    }
    $pdo = new PDO(
        'mysql:host=' . $host . ';port=' . $port . ';dbname=' . $name . ';charset=utf8mb4',
        $user,
        $pass,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES => false]
    );
    $pdo->exec("CREATE TABLE IF NOT EXISTS pos_owner (
        id TINYINT UNSIGNED NOT NULL PRIMARY KEY,
        username VARCHAR(80) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    $pdo->exec("CREATE TABLE IF NOT EXISTS pos_sessions (
        token_hash CHAR(64) NOT NULL PRIMARY KEY,
        expires_at DATETIME NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        INDEX (expires_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    $pdo->exec("CREATE TABLE IF NOT EXISTS pos_meta (
        id TINYINT UNSIGNED NOT NULL PRIMARY KEY,
        revision BIGINT UNSIGNED NOT NULL DEFAULT 0
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    $pdo->exec("INSERT IGNORE INTO pos_meta (id, revision) VALUES (1, 0)");
    $pdo->exec("CREATE TABLE IF NOT EXISTS pos_records (
        record_type VARCHAR(32) NOT NULL,
        record_id VARCHAR(191) NOT NULL,
        payload LONGTEXT NOT NULL,
        PRIMARY KEY (record_type, record_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    return $pdo;
}
function body(): array {
    $raw = file_get_contents('php://input');
    $data = json_decode($raw ?: '{}', true);
    if (!is_array($data)) respond(400, ['error' => 'Invalid JSON request.']);
    return $data;
}
function bearer(): string {
    $header = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (preg_match('/^Bearer\s+([A-Za-z0-9_-]+)$/i', $header, $m)) return $m[1];
    return '';
}
function requireOwner(PDO $pdo): string {
    $token = bearer();
    if ($token === '') respond(401, ['error' => 'Please sign in again.']);
    $hash = hash('sha256', $token);
    $q = $pdo->prepare('SELECT token_hash FROM pos_sessions WHERE token_hash = ? AND expires_at > UTC_TIMESTAMP()');
    $q->execute([$hash]);
    if (!$q->fetch()) respond(401, ['error' => 'Your session expired. Please sign in again.']);
    return $hash;
}
try {
    $pdo = db();
    $action = $_GET['action'] ?? '';
    if ($action === 'health' && $_SERVER['REQUEST_METHOD'] === 'GET') {
        respond(200, ['ok' => true, 'service' => 'joshua-pos-api', 'database' => 'connected']);
    }
    if ($action === 'auth_status' && $_SERVER['REQUEST_METHOD'] === 'GET') {
        $configured = (bool)$pdo->query('SELECT id FROM pos_owner WHERE id = 1')->fetch();
        respond(200, ['configured' => $configured]);
    }
    if ($action === 'setup' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $input = body();
        $username = strtolower(trim((string)($input['username'] ?? '')));
        $password = (string)($input['password'] ?? '');
        if (strlen($username) < 3 || strlen($username) > 80) respond(422, ['error' => 'Username must be 3 to 80 characters.']);
        if (strlen($password) < 8 || strlen($password) > 200) respond(422, ['error' => 'Password must be at least 8 characters.']);
        $pdo->beginTransaction();
        $pdo->query('SELECT id FROM pos_owner WHERE id = 1 FOR UPDATE');
        if ($pdo->query('SELECT id FROM pos_owner WHERE id = 1')->fetch()) {
            $pdo->rollBack();
            respond(409, ['error' => 'The owner account has already been created. Please sign in.']);
        }
        $q = $pdo->prepare('INSERT INTO pos_owner (id, username, password_hash) VALUES (1, ?, ?)');
        $q->execute([$username, password_hash($password, PASSWORD_DEFAULT)]);
        $pdo->commit();
        $token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $q = $pdo->prepare('INSERT INTO pos_sessions (token_hash, expires_at) VALUES (?, DATE_ADD(UTC_TIMESTAMP(), INTERVAL 30 DAY))');
        $q->execute([hash('sha256', $token)]);
        respond(201, ['token' => $token, 'username' => $username]);
    }
    if ($action === 'login' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $input = body();
        $username = strtolower(trim((string)($input['username'] ?? '')));
        $password = (string)($input['password'] ?? '');
        $q = $pdo->prepare('SELECT username, password_hash FROM pos_owner WHERE id = 1 AND username = ?');
        $q->execute([$username]);
        $owner = $q->fetch();
        if (!$owner || !password_verify($password, $owner['password_hash'])) respond(401, ['error' => 'Incorrect username or password.']);
        $token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $q = $pdo->prepare('INSERT INTO pos_sessions (token_hash, expires_at) VALUES (?, DATE_ADD(UTC_TIMESTAMP(), INTERVAL 30 DAY))');
        $q->execute([hash('sha256', $token)]);
        respond(200, ['token' => $token, 'username' => $owner['username']]);
    }
    if ($action === 'logout' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $token = bearer();
        if ($token !== '') {
            $q = $pdo->prepare('DELETE FROM pos_sessions WHERE token_hash = ?');
            $q->execute([hash('sha256', $token)]);
        }
        respond(200, ['ok' => true]);
    }
    if ($action === 'state' && $_SERVER['REQUEST_METHOD'] === 'GET') {
        requireOwner($pdo);
        $revision = (int)$pdo->query('SELECT revision FROM pos_meta WHERE id = 1')->fetchColumn();
        $state = ['products'=>[], 'sales'=>[], 'suppliers'=>[], 'purchases'=>[], 'expenses'=>[], 'utang'=>[], 'settings'=>[], 'dark'=>false];
        foreach ($pdo->query('SELECT record_type, record_id, payload FROM pos_records') as $row) {
            $value = json_decode($row['payload'], true);
            if ($row['record_type'] === 'settings') $state['settings'] = is_array($value) ? $value : [];
            elseif ($row['record_type'] === 'app') $state['dark'] = (bool)($value['dark'] ?? false);
            elseif (array_key_exists($row['record_type'], $state) && is_array($value)) $state[$row['record_type']][] = $value;
        }
        respond(200, ['revision' => $revision, 'state' => $state]);
    }
    if ($action === 'state' && $_SERVER['REQUEST_METHOD'] === 'PUT') {
        requireOwner($pdo);
        $input = body();
        $state = $input['state'] ?? null;
        $expected = filter_var($input['expectedRevision'] ?? null, FILTER_VALIDATE_INT);
        if (!is_array($state) || $expected === false || $expected === null) respond(422, ['error' => 'State or revision is invalid.']);
        $types = ['products','sales','suppliers','purchases','expenses','utang'];
        $pdo->beginTransaction();
        $current = (int)$pdo->query('SELECT revision FROM pos_meta WHERE id = 1 FOR UPDATE')->fetchColumn();
        if ($current !== $expected) {
            $pdo->rollBack();
            respond(409, ['error' => 'The database changed in another session. Reload the latest data before saving.', 'revision' => $current]);
        }
        $pdo->exec('DELETE FROM pos_records');
        $insert = $pdo->prepare('INSERT INTO pos_records (record_type, record_id, payload) VALUES (?, ?, ?)');
        foreach ($types as $type) {
            $items = $state[$type] ?? [];
            if (!is_array($items)) continue;
            foreach ($items as $item) {
                if (!is_array($item)) continue;
                $id = (string)($item['id'] ?? '');
                if ($id === '') continue;
                $insert->execute([$type, $id, json_encode($item, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)]);
            }
        }
        $settings = is_array($state['settings'] ?? null) ? $state['settings'] : [];
        $insert->execute(['settings', 'main', json_encode($settings, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)]);
        $insert->execute(['app', 'main', json_encode(['dark'=>(bool)($state['dark'] ?? false)])]);
        $newRevision = $current + 1;
        $q = $pdo->prepare('UPDATE pos_meta SET revision = ? WHERE id = 1');
        $q->execute([$newRevision]);
        $pdo->commit();
        respond(200, ['ok' => true, 'revision' => $newRevision]);
    }
    respond(404, ['error' => 'Unknown API action.']);
} catch (Throwable $e) {
    if (isset($pdo) && $pdo instanceof PDO && $pdo->inTransaction()) $pdo->rollBack();
    error_log('JOSHUA POS API error: ' . $e->getMessage());
    respond(500, ['error' => 'The POS service encountered a server error. Check Wasmer logs for details.']);
}
