CREATE TABLE IF NOT EXISTS sessions (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NOT NULL,
    access_token_hash CHAR(64) NOT NULL,
    refresh_token_hash CHAR(64) NOT NULL,
    access_expires_at DATETIME(6) NOT NULL,
    refresh_expires_at DATETIME(6) NOT NULL,
    revoked_at DATETIME(6) NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP (6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_sessions_refresh_token_hash (refresh_token_hash),
    KEY idx_sessions_user_id (user_id),
    KEY idx_sessions_access_token_hash (access_token_hash),
    CONSTRAINT fk_sessions_user_id FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;