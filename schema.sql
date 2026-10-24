-- ============================================================================
-- FLAME_CLOUD (FIBA — Future Integration & Backup Architecture)
-- Backend Module 4: MySQL Database Schema (backend/schema.sql)
-- Database: `fiba_cloud_db`
-- ============================================================================

CREATE DATABASE IF NOT EXISTS `fiba_cloud_db`
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE `fiba_cloud_db`;

CREATE TABLE IF NOT EXISTS `fiba_users` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `fiba_id` VARCHAR(120) NOT NULL COMMENT 'e.g. architect@fiba',
  `full_name` VARCHAR(160) NOT NULL,
  `email` VARCHAR(190) NOT NULL,
  `password_hash` VARCHAR(255) NOT NULL COMMENT 'BCRYPT cost=12 hash',
  `allocated_storage_bytes` BIGINT UNSIGNED NOT NULL DEFAULT 5368709120 COMMENT '5 GB Free Quota',
  `used_storage_bytes` BIGINT UNSIGNED NOT NULL DEFAULT 0,
  `is_deleted_on_phone` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '1 = Wiped on phone, preserved in Admin File',
  `security_status` VARCHAR(80) NOT NULL DEFAULT 'VERIFIED_SECURE',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_fiba_active_lookup` (`is_deleted_on_phone`, `fiba_id`),
  KEY `idx_email_active_lookup` (`is_deleted_on_phone`, `email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `fiba_sessions` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT UNSIGNED NOT NULL,
  `token_hash` CHAR(64) NOT NULL COMMENT 'SHA-256 hash of 256-bit Bearer token',
  `ip_address` VARCHAR(45) NOT NULL,
  `user_agent` VARCHAR(255) NOT NULL,
  `expires_at` DATETIME NOT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_token_hash` (`token_hash`),
  KEY `idx_user_sessions` (`user_id`),
  CONSTRAINT `fk_sessions_user` FOREIGN KEY (`user_id`) REFERENCES `fiba_users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `fiba_storage_files` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT UNSIGNED NOT NULL,
  `fiba_id` VARCHAR(120) NOT NULL,
  `original_name` VARCHAR(255) NOT NULL,
  `stored_name` VARCHAR(255) NOT NULL,
  `folder_path` VARCHAR(160) NOT NULL DEFAULT 'root',
  `mime_type` VARCHAR(120) NOT NULL,
  `extension` VARCHAR(24) NOT NULL,
  `size_bytes` BIGINT UNSIGNED NOT NULL,
  `sha256_hash` CHAR(64) NOT NULL,
  `public_url` VARCHAR(512) NOT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_stored_name` (`stored_name`),
  KEY `idx_user_files` (`user_id`, `created_at`),
  CONSTRAINT `fk_files_user` FOREIGN KEY (`user_id`) REFERENCES `fiba_users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `fiba_admin_backups` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT UNSIGNED NOT NULL,
  `fiba_id` VARCHAR(120) NOT NULL,
  `email` VARCHAR(190) NOT NULL,
  `category` VARCHAR(80) NOT NULL DEFAULT 'DELETED_ACCOUNT_ADMIN_BACKUP',
  `status_tag` VARCHAR(80) NOT NULL DEFAULT 'WIPED ON PHONE • SAVED IN ADMIN FILE',
  `snapshot_json` LONGTEXT NOT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_backup_fiba_id` (`fiba_id`),
  KEY `idx_backup_email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
