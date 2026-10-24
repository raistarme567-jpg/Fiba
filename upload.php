<?php
/**
 * ============================================================================
 * FLAME_CLOUD (FIBA — Future Integration & Backup Architecture)
 * Backend Module 3: Secure Cloud File Upload & Storage Engine (backend/upload.php)
 * ============================================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/db.php';

fibaApplySecurityHeaders();

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    fibaJsonResponse(405, [
        'status'  => 'error',
        'code'    => 'METHOD_NOT_ALLOWED',
        'message' => 'Only POST multipart/form-data requests are accepted.'
    ]);
}

$pdo = getFibaDatabaseConnection();

$authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
$userId     = null;
$fibaId     = 'anonymous@fiba';

if (preg_match('/^Bearer\s+([a-f0-9]{64})$/i', $authHeader, $matches)) {
    $rawToken  = $matches[1];
    $tokenHash = hash('sha256', $rawToken);

    $stmt = $pdo->prepare('
        SELECT u.id, u.fiba_id, u.allocated_storage_bytes, u.used_storage_bytes
        FROM fiba_sessions s
        INNER JOIN fiba_users u ON u.id = s.user_id
        WHERE s.token_hash = :token_hash
          AND s.expires_at > NOW()
          AND u.is_deleted_on_phone = 0
        LIMIT 1
    ');
    $stmt->execute([':token_hash' => $tokenHash]);
    $authenticatedUser = $stmt->fetch();

    if (!$authenticatedUser) {
        fibaJsonResponse(401, [
            'status'  => 'error',
            'code'    => 'UNAUTHORIZED_SESSION',
            'message' => 'Invalid or expired FIBA session token.'
        ]);
    }

    $userId = (int) $authenticatedUser['id'];
    $fibaId = (string) $authenticatedUser['fiba_id'];
} else {
    fibaJsonResponse(401, [
        'status'  => 'error',
        'code'    => 'MISSING_BEARER_TOKEN',
        'message' => 'Authorization: Bearer <token> header is required to upload files to FIBA Cloud.'
    ]);
}

if (!isset($_FILES['file']) || !is_array($_FILES['file'])) {
    fibaJsonResponse(400, [
        'status'  => 'error',
        'code'    => 'NO_FILE_UPLOADED',
        'message' => 'No file payload found under form field "file".'
    ]);
}

$file = $_FILES['file'];

if (($file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
    $uploadErrors = [
        UPLOAD_ERR_INI_SIZE   => 'Uploaded file exceeds server upload_max_filesize directive.',
        UPLOAD_ERR_FORM_SIZE  => 'Uploaded file exceeds MAX_FILE_SIZE directive.',
        UPLOAD_ERR_PARTIAL    => 'The uploaded file was only partially received.',
        UPLOAD_ERR_NO_FILE    => 'No file was uploaded.',
        UPLOAD_ERR_NO_TMP_DIR => 'Missing temporary upload folder on server.',
        UPLOAD_ERR_CANT_WRITE => 'Failed to write file to disk.',
        UPLOAD_ERR_EXTENSION  => 'A PHP extension stopped the file upload.',
    ];
    $errCode = (int) ($file['error'] ?? UPLOAD_ERR_NO_FILE);
    fibaJsonResponse(400, [
        'status'  => 'error',
        'code'    => 'UPLOAD_TRANSPORT_ERROR',
        'message' => $uploadErrors[$errCode] ?? 'Unknown file upload error.'
    ]);
}

$tmpPath      = (string) $file['tmp_name'];
$originalName = (string) $file['name'];
$fileSize     = (int) $file['size'];

if (!is_uploaded_file($tmpPath)) {
    fibaJsonResponse(400, [
        'status'  => 'error',
        'code'    => 'INVALID_UPLOAD_SOURCE',
        'message' => 'Security check failed: file was not uploaded via HTTP POST.'
    ]);
}

$maxFileSizeBytes = 50 * 1024 * 1024;
if ($fileSize <= 0 || $fileSize > $maxFileSizeBytes) {
    fibaJsonResponse(413, [
        'status'         => 'error',
        'code'           => 'FILE_SIZE_LIMIT_EXCEEDED',
        'message'        => 'File size must be between 1 byte and 50 MB.',
        'max_size_mb'    => 50,
        'uploaded_bytes' => $fileSize
    ]);
}

$allocatedBytes = (int) $authenticatedUser['allocated_storage_bytes'];
$usedBytes      = (int) $authenticatedUser['used_storage_bytes'];

if (($usedBytes + $fileSize) > $allocatedBytes) {
    fibaJsonResponse(403, [
        'status'          => 'error',
        'code'            => 'STORAGE_QUOTA_EXCEEDED',
        'message'         => 'Upload exceeds your 5 GB FIBA Cloud Storage allocation. Request a Garage Project upgrade to expand storage.',
        'allocated_bytes' => $allocatedBytes,
        'used_bytes'      => $usedBytes,
        'required_bytes'  => $fileSize
    ]);
}

$allowedMimeMap = [
    'image/jpeg'      => ['jpg', 'jpeg'],
    'image/png'       => ['png'],
    'image/webp'      => ['webp'],
    'image/gif'       => ['gif'],
    'image/svg+xml'   => ['svg'],
    'application/pdf' => ['pdf'],
    'text/plain'      => ['txt', 'md', 'csv', 'log'],
    'text/csv'        => ['csv'],
    'application/json'=> ['json'],
    'application/msword' => ['doc'],
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document' => ['docx'],
    'application/zip'              => ['zip'],
    'application/x-zip-compressed' => ['zip'],
    'application/gzip'             => ['gz', 'tgz'],
    'application/x-tar'            => ['tar'],
];

$finfo        = new finfo(FILEINFO_MIME_TYPE);
$realMime     = (string) $finfo->file($tmpPath);
$rawExtension = strtolower((string) pathinfo($originalName, PATHINFO_EXTENSION));

if (preg_match('/\.(php\d?|phtml|phar|cgi|pl|py|sh|asp|aspx|jsp|exe|bat|cmd)\b/i', $originalName)) {
    fibaJsonResponse(415, [
        'status'  => 'error',
        'code'    => 'EXECUTABLE_FILENAME_BLOCKED',
        'message' => 'Executable or script extensions are strictly forbidden by FIBA Security.'
    ]);
}

if (
    !isset($allowedMimeMap[$realMime]) ||
    !in_array($rawExtension, $allowedMimeMap[$realMime], true)
) {
    fibaJsonResponse(415, [
        'status'        => 'error',
        'code'          => 'UNSUPPORTED_FILE_TYPE',
        'message'       => 'File type or extension is not permitted. Allowed: images (JPG, PNG, WEBP, GIF, SVG), documents (PDF, TXT, MD, CSV, JSON, DOC, DOCX), and archives (ZIP, TAR, GZ).',
        'detected_mime' => $realMime,
        'extension'     => $rawExtension
    ]);
}

$sha256Checksum = hash_file('sha256', $tmpPath);
$uniqueToken    = uniqid('fiba_', true) . '_' . bin2hex(random_bytes(8));
$safeStoredName = preg_replace('/[^a-zA-Z0-9_.-]/', '', $uniqueToken) . '.' . $rawExtension;

$uploadDir = __DIR__ . '/uploads';
if (!is_dir($uploadDir)) {
    if (!mkdir($uploadDir, 0750, true) && !is_dir($uploadDir)) {
        fibaJsonResponse(500, [
            'status'  => 'error',
            'code'    => 'STORAGE_DIR_CREATION_FAILED',
            'message' => 'Server failed to initialize the /uploads/ storage directory.'
        ]);
    }
}

$htaccessFile = $uploadDir . '/.htaccess';
if (!file_exists($htaccessFile)) {
    $htaccessRules = <<<HTACCESS
# FIBA Cloud Storage Security Policy — Disable Script Execution
Options -Indexes -ExecCGI
RemoveHandler .php .phtml .php3 .php4 .php5 .php7 .php8 .phar .cgi .pl .py
RemoveType .php .phtml .php3 .php4 .php5 .php7 .php8 .phar .cgi .pl .py
php_flag engine off
<FilesMatch "\.(php\d?|phtml|phar|cgi|pl|py|sh|exe)$">
    Require all denied
</FilesMatch>
HTACCESS;
    @file_put_contents($htaccessFile, $htaccessRules);
}

$destinationPath = $uploadDir . '/' . $safeStoredName;

if (!move_uploaded_file($tmpPath, $destinationPath)) {
    fibaJsonResponse(500, [
        'status'  => 'error',
        'code'    => 'FILE_WRITE_FAILED',
        'message' => 'Could not move uploaded file into FIBA secure storage.'
    ]);
}

@chmod($destinationPath, 0640);

$sanitizedOriginalName = fibaSanitizeInput(basename($originalName));
$bucketFolder          = fibaSanitizeInput($_POST['folder'] ?? 'root');
$scheme                = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
$host                  = $_SERVER['HTTP_HOST'] ?? 'localhost';
$basePath              = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? ''), '/\\');
$publicUrl             = "{$scheme}://{$host}{$basePath}/uploads/{$safeStoredName}";

try {
    $pdo->beginTransaction();

    $insertStmt = $pdo->prepare('
        INSERT INTO fiba_storage_files (
            user_id,
            fiba_id,
            original_name,
            stored_name,
            folder_path,
            mime_type,
            extension,
            size_bytes,
            sha256_hash,
            public_url,
            created_at
        ) VALUES (
            :user_id,
            :fiba_id,
            :original_name,
            :stored_name,
            :folder_path,
            :mime_type,
            :extension,
            :size_bytes,
            :sha256_hash,
            :public_url,
            NOW()
        )
    ');

    $insertStmt->execute([
        ':user_id'       => $userId,
        ':fiba_id'       => $fibaId,
        ':original_name' => $sanitizedOriginalName,
        ':stored_name'   => $safeStoredName,
        ':folder_path'   => $bucketFolder,
        ':mime_type'     => $realMime,
        ':extension'     => $rawExtension,
        ':size_bytes'    => $fileSize,
        ':sha256_hash'   => $sha256Checksum,
        ':public_url'    => $publicUrl,
    ]);

    $fileId = (int) $pdo->lastInsertId();

    $updateQuotaStmt = $pdo->prepare('
        UPDATE fiba_users
        SET used_storage_bytes = used_storage_bytes + :size_bytes
        WHERE id = :user_id
    ');
    $updateQuotaStmt->execute([
        ':size_bytes' => $fileSize,
        ':user_id'    => $userId,
    ]);

    $pdo->commit();
} catch (PDOException $e) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    @unlink($destinationPath);
    error_log('[FIBA UPLOAD DB ERROR] ' . $e->getMessage());

    fibaJsonResponse(500, [
        'status'  => 'error',
        'code'    => 'METADATA_PERSISTENCE_FAILED',
        'message' => 'Failed to record file metadata in FIBA Cloud database.'
    ]);
}

fibaJsonResponse(201, [
    'status'  => 'success',
    'message' => 'File uploaded and verified in FIBA Cloud Storage.',
    'file'    => [
        'file_id'       => $fileId,
        'owner_fiba_id' => $fibaId,
        'original_name' => $sanitizedOriginalName,
        'stored_name'   => $safeStoredName,
        'folder'        => $bucketFolder,
        'mime_type'     => $realMime,
        'extension'     => $rawExtension,
        'size_bytes'    => $fileSize,
        'size_kb'       => round($fileSize / 1024, 2),
        'sha256_hash'   => $sha256Checksum,
        'public_url'    => $publicUrl,
        'uploaded_at'   => gmdate('c'),
    ],
    'quota'   => [
        'allocated_bytes' => $allocatedBytes,
        'used_bytes'      => $usedBytes + $fileSize,
        'remaining_bytes' => max(0, $allocatedBytes - ($usedBytes + $fileSize)),
    ]
]);
