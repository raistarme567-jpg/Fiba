<?php
/**
 * ============================================================================
 * FLAME_CLOUD (FIBA — Future Integration & Backup Architecture)
 * Backend Module 2: User Authentication & Identity REST API (backend/auth.php)
 * ============================================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/db.php';

fibaApplySecurityHeaders();

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    fibaJsonResponse(405, [
        'status'  => 'error',
        'code'    => 'METHOD_NOT_ALLOWED',
        'message' => 'Only POST requests with JSON or form payload are accepted.'
    ]);
}

$pdo = getFibaDatabaseConnection();

$rawBody = file_get_contents('php://input');
$input   = [];
if (is_string($rawBody) && trim($rawBody) !== '') {
    $decoded = json_decode($rawBody, true);
    if (is_array($decoded)) {
        $input = $decoded;
    }
}
if (empty($input) && !empty($_POST)) {
    $input = $_POST;
}

$action = strtolower(trim((string) ($input['action'] ?? $_GET['action'] ?? '')));

function fibaNormalizeHandle(string $rawHandle): string
{
    $prefix = strtolower(trim($rawHandle));
    if (str_contains($prefix, '@')) {
        $prefix = explode('@', $prefix)[0];
    }
    $clean = preg_replace('/[^a-z0-9_.-]/', '', $prefix) ?: '';
    return $clean !== '' ? "{$clean}@fiba" : '';
}

function fibaIssueSessionToken(PDO $pdo, int $userId): array
{
    $rawToken  = bin2hex(random_bytes(32));
    $tokenHash = hash('sha256', $rawToken);
    $expiresAt = gmdate('Y-m-d H:i:s', time() + (86400 * 7));

    $stmt = $pdo->prepare('
        INSERT INTO fiba_sessions (user_id, token_hash, ip_address, user_agent, expires_at, created_at)
        VALUES (:user_id, :token_hash, :ip_address, :user_agent, :expires_at, NOW())
    ');
    $stmt->execute([
        ':user_id'    => $userId,
        ':token_hash' => $tokenHash,
        ':ip_address' => substr((string) ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0'), 0, 45),
        ':user_agent' => substr(fibaSanitizeInput($_SERVER['HTTP_USER_AGENT'] ?? 'FIBA-Client'), 0, 255),
        ':expires_at' => $expiresAt,
    ]);

    return [
        'access_token' => $rawToken,
        'token_type'   => 'Bearer',
        'expires_in'   => 86400 * 7,
        'expires_at'   => $expiresAt . 'Z',
    ];
}

if ($action === 'register') {
    $rawHandle = (string) ($input['fiba_id'] ?? $input['username'] ?? '');
    $fullName  = fibaSanitizeInput((string) ($input['full_name'] ?? ''));
    $email     = strtolower(trim((string) ($input['email'] ?? '')));
    $password  = (string) ($input['password'] ?? '');

    $fibaId = fibaNormalizeHandle($rawHandle);

    if ($fibaId === '' || strlen($fibaId) < 8) {
        fibaJsonResponse(400, [
            'status'  => 'error',
            'code'    => 'INVALID_FIBA_HANDLE',
            'message' => 'Please provide a valid FIBA handle (at least 3 alphanumeric characters before @fiba).'
        ]);
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        fibaJsonResponse(400, [
            'status'  => 'error',
            'code'    => 'INVALID_EMAIL',
            'message' => 'Please provide a valid recovery email address.'
        ]);
    }

    if (strlen($password) < 8) {
        fibaJsonResponse(400, [
            'status'  => 'error',
            'code'    => 'WEAK_PASSWORD',
            'message' => 'Password must be at least 8 characters long.'
        ]);
    }

    if ($fullName === '') {
        $fullName = ucfirst(explode('@', $fibaId)[0]);
    }

    $checkStmt = $pdo->prepare('
        SELECT id, fiba_id, email
        FROM fiba_users
        WHERE is_deleted_on_phone = 0
          AND (fiba_id = :fiba_id OR email = :email)
        LIMIT 1
    ');
    $checkStmt->execute([
        ':fiba_id' => $fibaId,
        ':email'   => $email,
    ]);
    $existingActive = $checkStmt->fetch();

    if ($existingActive) {
        fibaJsonResponse(409, [
            'status'  => 'error',
            'code'    => 'ACCOUNT_ALREADY_ACTIVE',
            'message' => 'An active FIBA account with this @fiba handle or email already exists on this device. Please log in instead.'
        ]);
    }

    $passwordHash  = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
    $fiveGbInBytes = 5 * 1024 * 1024 * 1024;

    try {
        $insertUser = $pdo->prepare('
            INSERT INTO fiba_users (
                fiba_id,
                full_name,
                email,
                password_hash,
                allocated_storage_bytes,
                used_storage_bytes,
                is_deleted_on_phone,
                security_status,
                created_at
            ) VALUES (
                :fiba_id,
                :full_name,
                :email,
                :password_hash,
                :allocated_bytes,
                0,
                0,
                :security_status,
                NOW()
            )
        ');
        $insertUser->execute([
            ':fiba_id'         => $fibaId,
            ':full_name'       => $fullName,
            ':email'           => $email,
            ':password_hash'   => $passwordHash,
            ':allocated_bytes' => $fiveGbInBytes,
            ':security_status' => 'VERIFIED_SECURE',
        ]);

        $newUserId = (int) $pdo->lastInsertId();
        $session   = fibaIssueSessionToken($pdo, $newUserId);

        fibaJsonResponse(201, [
            'status'  => 'success',
            'message' => "FIBA account {$fibaId} registered with 5 GB automatic cloud storage.",
            'user'    => [
                'user_id'                 => $newUserId,
                'fiba_id'                 => $fibaId,
                'full_name'               => $fullName,
                'email'                   => $email,
                'allocated_storage_gb'    => 5,
                'allocated_storage_bytes' => $fiveGbInBytes,
                'used_storage_bytes'      => 0,
                'security_status'         => 'VERIFIED_SECURE',
            ],
            'session' => $session,
        ]);
    } catch (PDOException $e) {
        error_log('[FIBA AUTH REGISTER ERROR] ' . $e->getMessage());
        fibaJsonResponse(500, [
            'status'  => 'error',
            'code'    => 'REGISTRATION_FAILED',
            'message' => 'Could not complete account registration at this time.'
        ]);
    }
}

if ($action === 'login') {
    $identifier = strtolower(trim((string) ($input['identifier'] ?? $input['fiba_id'] ?? $input['email'] ?? '')));
    $password   = (string) ($input['password'] ?? '');

    if ($identifier === '' || $password === '') {
        fibaJsonResponse(400, [
            'status'  => 'error',
            'code'    => 'MISSING_CREDENTIALS',
            'message' => 'Both FIBA ID (or Email) and Password are required.'
        ]);
    }

    $normalizedFibaId = str_contains($identifier, '@') ? $identifier : "{$identifier}@fiba";

    $stmt = $pdo->prepare('
        SELECT id, fiba_id, full_name, email, password_hash,
               allocated_storage_bytes, used_storage_bytes, security_status
        FROM fiba_users
        WHERE is_deleted_on_phone = 0
          AND (fiba_id = :fiba_id OR email = :email)
        ORDER BY id DESC
        LIMIT 1
    ');
    $stmt->execute([
        ':fiba_id' => $normalizedFibaId,
        ':email'   => $identifier,
    ]);
    $user = $stmt->fetch();

    $dummyHash       = '$2y$12$usesomesillystringfore7hnbRJHxXVLeakoG8K30oukPsA.ztMG';
    $hashToCheck     = $user ? (string) $user['password_hash'] : $dummyHash;
    $isValidPassword = password_verify($password, $hashToCheck);

    if (!$user || !$isValidPassword) {
        fibaJsonResponse(401, [
            'status'  => 'error',
            'code'    => 'INVALID_CREDENTIALS',
            'message' => 'Invalid FIBA ID / Email or password.'
        ]);
    }

    $userId  = (int) $user['id'];
    $session = fibaIssueSessionToken($pdo, $userId);

    fibaJsonResponse(200, [
        'status'  => 'success',
        'message' => 'Authenticated into FIBA Identity Hub.',
        'user'    => [
            'user_id'                 => $userId,
            'fiba_id'                 => $user['fiba_id'],
            'full_name'               => $user['full_name'],
            'email'                   => $user['email'],
            'allocated_storage_gb'    => round(((int) $user['allocated_storage_bytes']) / (1024 * 1024 * 1024), 2),
            'allocated_storage_bytes' => (int) $user['allocated_storage_bytes'],
            'used_storage_bytes'      => (int) $user['used_storage_bytes'],
            'security_status'         => $user['security_status'],
        ],
        'session' => $session,
    ]);
}

if ($action === 'logout') {
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
    if (preg_match('/^Bearer\s+([a-f0-9]{64})$/i', $authHeader, $matches)) {
        $tokenHash = hash('sha256', $matches[1]);
        $delStmt = $pdo->prepare('DELETE FROM fiba_sessions WHERE token_hash = :token_hash');
        $delStmt->execute([':token_hash' => $tokenHash]);
    }

    fibaJsonResponse(200, [
        'status'       => 'success',
        'signed_out'   => true,
        'redirect_url' => '../frontend/index.html#login',
        'message'      => 'Signed out of active FIBA phone session.'
    ]);
}

if ($action === 'delete_phone') {
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/^Bearer\s+([a-f0-9]{64})$/i', $authHeader, $matches)) {
        fibaJsonResponse(401, [
            'status'  => 'error',
            'code'    => 'MISSING_BEARER_TOKEN',
            'message' => 'Valid Bearer token is required to wipe account from phone.'
        ]);
    }

    $tokenHash = hash('sha256', $matches[1]);
    $stmt = $pdo->prepare('
        SELECT u.*
        FROM fiba_sessions s
        INNER JOIN fiba_users u ON u.id = s.user_id
        WHERE s.token_hash = :token_hash
          AND u.is_deleted_on_phone = 0
        LIMIT 1
    ');
    $stmt->execute([':token_hash' => $tokenHash]);
    $user = $stmt->fetch();

    if (!$user) {
        fibaJsonResponse(404, [
            'status'  => 'error',
            'code'    => 'ACCOUNT_NOT_FOUND',
            'message' => 'Active phone account not found or already wiped.'
        ]);
    }

    $userId = (int) $user['id'];

    try {
        $pdo->beginTransaction();

        $backupSnapshot = json_encode([
            'category'        => 'DELETED_ACCOUNT_ADMIN_BACKUP',
            'status'          => 'WIPED ON PHONE • SAVED IN ADMIN FILE',
            'user_id'         => $userId,
            'fiba_id'         => $user['fiba_id'],
            'full_name'       => $user['full_name'],
            'email'           => $user['email'],
            'used_bytes'      => (int) $user['used_storage_bytes'],
            'allocated_bytes' => (int) $user['allocated_storage_bytes'],
            'wiped_at_utc'    => gmdate('c'),
        ], JSON_UNESCAPED_SLASHES);

        $backupStmt = $pdo->prepare('
            INSERT INTO fiba_admin_backups (user_id, fiba_id, email, category, status_tag, snapshot_json, created_at)
            VALUES (:user_id, :fiba_id, :email, :category, :status_tag, :snapshot_json, NOW())
        ');
        $backupStmt->execute([
            ':user_id'       => $userId,
            ':fiba_id'       => $user['fiba_id'],
            ':email'         => $user['email'],
            ':category'      => 'DELETED_ACCOUNT_ADMIN_BACKUP',
            ':status_tag'    => 'WIPED ON PHONE • SAVED IN ADMIN FILE',
            ':snapshot_json' => $backupSnapshot,
        ]);

        $wipeStmt = $pdo->prepare('
            UPDATE fiba_users
            SET is_deleted_on_phone = 1,
                security_status = :status_tag
            WHERE id = :user_id
        ');
        $wipeStmt->execute([
            ':status_tag' => 'WIPED ON PHONE • SAVED IN ADMIN FILE',
            ':user_id'    => $userId,
        ]);

        $revokeStmt = $pdo->prepare('DELETE FROM fiba_sessions WHERE user_id = :user_id');
        $revokeStmt->execute([':user_id' => $userId]);

        $pdo->commit();

        fibaJsonResponse(200, [
            'status'                         => 'success',
            'deleted_from_phone'             => true,
            'saved_in_admin_file'            => true,
            'category'                       => 'DELETED_ACCOUNT_ADMIN_BACKUP',
            'status_tag'                     => 'WIPED ON PHONE • SAVED IN ADMIN FILE',
            'same_email_re_register_allowed' => true,
            'redirect_url'                   => '../frontend/index.html#login',
            'message'                        => "Account {$user['fiba_id']} wiped from phone while 100% preserved in Admin File. You can now re-register with {$user['email']}."
        ]);
    } catch (PDOException $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        error_log('[FIBA DELETE PHONE ERROR] ' . $e->getMessage());
        fibaJsonResponse(500, [
            'status'  => 'error',
            'code'    => 'PHONE_WIPE_FAILED',
            'message' => 'Failed to complete account wipe operation.'
        ]);
    }
}

fibaJsonResponse(400, [
    'status'            => 'error',
    'code'              => 'INVALID_ACTION',
    'message'           => 'Specify a valid "action": "register", "login", "logout", or "delete_phone".',
    'supported_actions' => ['register', 'login', 'logout', 'delete_phone']
]);
