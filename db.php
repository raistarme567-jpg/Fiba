<?php
/**
 * ============================================================================
 * FLAME_CLOUD (FIBA — Future Integration & Backup Architecture)
 * Backend Module 1: Secure MySQL PDO Database Connection (backend/db.php)
 * ============================================================================
 * Features:
 * - Connects to `fiba_cloud_db` via PDO with strict prepared statements
 *   (ATTR_EMULATE_PREPARES = false) to guarantee 100% SQL Injection protection.
 * - Configures strict HTTP Security Headers (XSS, Clickjacking, MIME-Sniffing,
 *   CORS) and JSON output helper functions.
 * - Catches PDOException errors cleanly and logs internally without ever
 *   leaking database credentials, hostnames, or stack traces to the client.
 */

declare(strict_types=1);

if (basename($_SERVER['PHP_SELF'] ?? '') === 'db.php') {
    http_response_code(403);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode([
        'status'  => 'error',
        'code'    => 'FORBIDDEN_DIRECT_ACCESS',
        'message' => 'Direct access to db.php is prohibited.'
    ]);
    exit;
}

function fibaApplySecurityHeaders(): void
{
    header('Content-Type: application/json; charset=utf-8');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('X-XSS-Protection: 1; mode=block');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'");

    $allowedOrigin = getenv('FIBA_ALLOWED_ORIGIN') ?: '*';
    header("Access-Control-Allow-Origin: {$allowedOrigin}");
    header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Authorization, X-FIBA-Project-ID, X-Requested-With');
    header('Access-Control-Max-Age: 86400');

    if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') {
        http_response_code(204);
        exit;
    }
}

function fibaJsonResponse(int $statusCode, array $payload): never
{
    http_response_code($statusCode);
    echo json_encode(
        $payload,
        JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT
    );
    exit;
}

function fibaSanitizeInput(?string $value): string
{
    if ($value === null) {
        return '';
    }
    $trimmed = trim($value);
    $clean = str_replace("\0", '', $trimmed);
    return htmlspecialchars($clean, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function getFibaDatabaseConnection(): PDO
{
    static $pdo = null;

    if ($pdo instanceof PDO) {
        return $pdo;
    }

    $dbHost    = getenv('FIBA_DB_HOST') ?: '127.0.0.1';
    $dbPort    = getenv('FIBA_DB_PORT') ?: '3306';
    $dbName    = getenv('FIBA_DB_NAME') ?: 'fiba_cloud_db';
    $dbUser    = getenv('FIBA_DB_USER') ?: 'fiba_admin';
    $dbPass    = getenv('FIBA_DB_PASS') ?: 'ChangeThisStrongPassword!2026';
    $dbCharset = 'utf8mb4';

    $dsn = "mysql:host={$dbHost};port={$dbPort};dbname={$dbName};charset={$dbCharset}";

    $options = [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
        PDO::ATTR_STRINGIFY_FETCHES  => false,
        PDO::ATTR_TIMEOUT            => 5,
    ];

    try {
        $pdo = new PDO($dsn, $dbUser, $dbPass, $options);
        return $pdo;
    } catch (PDOException $e) {
        error_log('[FIBA DB CRITICAL] PDO Connection Failed: ' . $e->getMessage());

        fibaJsonResponse(500, [
            'status'    => 'error',
            'code'      => 'DB_CONNECTION_ERROR',
            'message'   => 'FIBA Cloud Database service is temporarily unavailable. Please try again shortly.',
            'timestamp' => gmdate('c')
        ]);
    }
}
