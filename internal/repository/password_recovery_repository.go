package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/fabricio948/system_login/internal/model"
)

// PasswordRecoveryRepository defines persistence operations for recovery codes.
type PasswordRecoveryRepository interface {
	Create(ctx context.Context, recovery *model.PasswordRecovery, now time.Time) error
	FindLatestByUserID(ctx context.Context, userID uint64) (*model.PasswordRecovery, error)
	IncrementFailedAttempts(ctx context.Context, id uint64) (int, error)
	MarkUsed(ctx context.Context, id uint64, usedAt time.Time) error
	Invalidate(ctx context.Context, id uint64, invalidatedAt time.Time) error
}

type passwordRecoveryRepository struct {
	db *sql.DB
}

// NewPasswordRecoveryRepository returns the MySQL-backed recovery repository.
func NewPasswordRecoveryRepository(db *sql.DB) PasswordRecoveryRepository {
	return &passwordRecoveryRepository{db: db}
}

const recoveryColumns = `id, user_id, code_hash, failed_attempts, expires_at,
	used_at, invalidated_at, created_at`

// Create invalidates any open code for the user before inserting the new one.
func (r *passwordRecoveryRepository) Create(ctx context.Context, recovery *model.PasswordRecovery, now time.Time) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("create recovery code: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx,
		`UPDATE password_recoveries
		 SET invalidated_at = ?
		 WHERE user_id = ? AND used_at IS NULL AND invalidated_at IS NULL`,
		now, recovery.UserID,
	); err != nil {
		return fmt.Errorf("invalidate previous recovery codes: %w", err)
	}

	recovery.CreatedAt = now
	result, err := tx.ExecContext(ctx,
		`INSERT INTO password_recoveries
		 (user_id, code_hash, failed_attempts, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		recovery.UserID,
		recovery.CodeHash,
		recovery.FailedAttempts,
		recovery.ExpiresAt,
		recovery.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("create recovery code: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("create recovery code: %w", err)
	}
	recovery.ID = uint64(id)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("create recovery code: %w", err)
	}
	return nil
}

func (r *passwordRecoveryRepository) FindLatestByUserID(ctx context.Context, userID uint64) (*model.PasswordRecovery, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+recoveryColumns+`
		 FROM password_recoveries
		 WHERE user_id = ?
		 ORDER BY created_at DESC, id DESC
		 LIMIT 1`,
		userID,
	)

	recovery, err := scanPasswordRecovery(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, model.ErrRecoveryCodeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find recovery code: %w", err)
	}
	return recovery, nil
}

func (r *passwordRecoveryRepository) IncrementFailedAttempts(ctx context.Context, id uint64) (int, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("increment recovery attempts: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx,
		`UPDATE password_recoveries SET failed_attempts = failed_attempts + 1 WHERE id = ?`,
		id,
	)
	if err != nil {
		return 0, fmt.Errorf("increment recovery attempts: %w", err)
	}
	if err := requireAffected(result, model.ErrRecoveryCodeNotFound); err != nil {
		return 0, err
	}

	var attempts int
	if err := tx.QueryRowContext(ctx,
		`SELECT failed_attempts FROM password_recoveries WHERE id = ?`,
		id,
	).Scan(&attempts); err != nil {
		return 0, fmt.Errorf("increment recovery attempts: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("increment recovery attempts: %w", err)
	}
	return attempts, nil
}

func (r *passwordRecoveryRepository) MarkUsed(ctx context.Context, id uint64, usedAt time.Time) error {
	return r.finalize(ctx, id, usedAt, true)
}

func (r *passwordRecoveryRepository) Invalidate(ctx context.Context, id uint64, invalidatedAt time.Time) error {
	return r.finalize(ctx, id, invalidatedAt, false)
}

func (r *passwordRecoveryRepository) finalize(ctx context.Context, id uint64, at time.Time, markUsed bool) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("finalize recovery code: %w", err)
	}
	defer tx.Rollback()

	var usedAt, invalidatedAt sql.NullTime
	err = tx.QueryRowContext(ctx,
		`SELECT used_at, invalidated_at FROM password_recoveries WHERE id = ? FOR UPDATE`,
		id,
	).Scan(&usedAt, &invalidatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.ErrRecoveryCodeNotFound
	}
	if err != nil {
		return fmt.Errorf("finalize recovery code: %w", err)
	}
	if usedAt.Valid {
		return model.ErrRecoveryCodeUsed
	}
	if invalidatedAt.Valid {
		return model.ErrRecoveryCodeInvalidated
	}

	query := `UPDATE password_recoveries SET invalidated_at = ? WHERE id = ?`
	if markUsed {
		query = `UPDATE password_recoveries SET used_at = ? WHERE id = ?`
	}
	if _, err := tx.ExecContext(ctx, query, at, id); err != nil {
		return fmt.Errorf("finalize recovery code: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("finalize recovery code: %w", err)
	}
	return nil
}

func scanPasswordRecovery(row scanner) (*model.PasswordRecovery, error) {
	var (
		recovery      model.PasswordRecovery
		usedAt        sql.NullTime
		invalidatedAt sql.NullTime
	)

	err := row.Scan(
		&recovery.ID,
		&recovery.UserID,
		&recovery.CodeHash,
		&recovery.FailedAttempts,
		&recovery.ExpiresAt,
		&usedAt,
		&invalidatedAt,
		&recovery.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	recovery.UsedAt = nullTimePtr(usedAt)
	recovery.InvalidatedAt = nullTimePtr(invalidatedAt)
	return &recovery, nil
}
