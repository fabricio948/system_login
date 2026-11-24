package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/fabricio948/system_login/internal/model"
)

// SessionRepository defines persistence operations for sessions.
type SessionRepository interface {
	Create(ctx context.Context, session *model.Session) error
	FindByAccessTokenHash(ctx context.Context, hash string) (*model.Session, error)
	FindByRefreshTokenHash(ctx context.Context, hash string) (*model.Session, error)
	Rotate(ctx context.Context, currentID uint64, revokedAt time.Time, next *model.Session) error
	Revoke(ctx context.Context, id uint64, revokedAt time.Time) error
	RevokeByUserID(ctx context.Context, userID uint64, revokedAt time.Time) (int64, error)
	DeleteExpired(ctx context.Context, now time.Time) (int64, error)
}

type sessionRepository struct {
	db *sql.DB
}

// NewSessionRepository returns the MySQL-backed session repository.
func NewSessionRepository(db *sql.DB) SessionRepository {
	return &sessionRepository{db: db}
}

const sessionColumns = `id, user_id, access_token_hash, refresh_token_hash,
	access_expires_at, refresh_expires_at, revoked_at, created_at`

func (r *sessionRepository) Create(ctx context.Context, session *model.Session) error {
	return insertSession(ctx, r.db, session)
}

func (r *sessionRepository) FindByAccessTokenHash(ctx context.Context, hash string) (*model.Session, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+sessionColumns+` FROM sessions WHERE access_token_hash = ? LIMIT 1`,
		hash,
	)
	return findSession(row, "find session by access token")
}

func (r *sessionRepository) FindByRefreshTokenHash(ctx context.Context, hash string) (*model.Session, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+sessionColumns+` FROM sessions WHERE refresh_token_hash = ? LIMIT 1`,
		hash,
	)
	return findSession(row, "find session by refresh token")
}

// Rotate revokes the current session and inserts its replacement atomically.
// Keeping the old row preserves the previous refresh hash for reuse detection.
func (r *sessionRepository) Rotate(ctx context.Context, currentID uint64, revokedAt time.Time, next *model.Session) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("rotate session: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx,
		`UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		revokedAt, currentID,
	)
	if err != nil {
		return fmt.Errorf("rotate session: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rotate session: %w", err)
	}
	if affected == 0 {
		return rotateConflict(ctx, tx, currentID)
	}

	if err := insertSession(ctx, tx, next); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("rotate session: %w", err)
	}
	return nil
}

func (r *sessionRepository) Revoke(ctx context.Context, id uint64, revokedAt time.Time) error {
	result, err := r.db.ExecContext(ctx,
		`UPDATE sessions SET revoked_at = ? WHERE id = ?`,
		revokedAt, id,
	)
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return requireAffected(result, model.ErrSessionNotFound)
}

func (r *sessionRepository) RevokeByUserID(ctx context.Context, userID uint64, revokedAt time.Time) (int64, error) {
	result, err := r.db.ExecContext(ctx,
		`UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`,
		revokedAt, userID,
	)
	if err != nil {
		return 0, fmt.Errorf("revoke user sessions: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("revoke user sessions: %w", err)
	}
	return affected, nil
}

func (r *sessionRepository) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	result, err := r.db.ExecContext(ctx,
		`DELETE FROM sessions WHERE refresh_expires_at < ?`,
		now,
	)
	if err != nil {
		return 0, fmt.Errorf("delete expired sessions: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("delete expired sessions: %w", err)
	}
	return affected, nil
}

func rotateConflict(ctx context.Context, tx *sql.Tx, id uint64) error {
	var exists bool
	if err := tx.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM sessions WHERE id = ?)`,
		id,
	).Scan(&exists); err != nil {
		return fmt.Errorf("rotate session: %w", err)
	}
	if !exists {
		return model.ErrSessionNotFound
	}
	return model.ErrSessionRevoked
}

func insertSession(ctx context.Context, db execer, session *model.Session) error {
	result, err := db.ExecContext(ctx,
		`INSERT INTO sessions
		 (user_id, access_token_hash, refresh_token_hash, access_expires_at, refresh_expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		session.UserID,
		session.AccessTokenHash,
		session.RefreshTokenHash,
		session.AccessExpiresAt,
		session.RefreshExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("insert session: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("insert session: %w", err)
	}
	session.ID = uint64(id)
	return nil
}

func findSession(row *sql.Row, operation string) (*model.Session, error) {
	session, err := scanSession(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, model.ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", operation, err)
	}
	return session, nil
}

func scanSession(row scanner) (*model.Session, error) {
	var (
		session   model.Session
		revokedAt sql.NullTime
	)

	err := row.Scan(
		&session.ID,
		&session.UserID,
		&session.AccessTokenHash,
		&session.RefreshTokenHash,
		&session.AccessExpiresAt,
		&session.RefreshExpiresAt,
		&revokedAt,
		&session.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	session.RevokedAt = nullTimePtr(revokedAt)
	return &session, nil
}
