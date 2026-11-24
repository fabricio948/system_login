CREATE TABLE IF NOT EXISTS password_recoveries (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NOT NULL,
    code_hash CHAR(64) NOT NULL,
    failed_attempts TINYINT UNSIGNED NOT NULL DEFAULT 0,
    expires_at DATETIME(6) NOT NULL,
    used_at DATETIME(6) NULL,
    invalidated_at DATETIME(6) NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP (6),
    PRIMARY KEY (id),
    KEY idx_password_recoveries_user_id (user_id),
    CONSTRAINT fk_password_recoveries_user_id FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;