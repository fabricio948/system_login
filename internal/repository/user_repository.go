package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/fabricio948/system_login/internal/model"
)

// UserRepository defines persistence operations for users.
type UserRepository interface {
	Create(ctx context.Context, user *model.User) error
	FindByEmail(ctx context.Context, email string) (*model.User, error)
	FindByID(ctx context.Context, id uint64) (*model.User, error)
	ExistsByEmail(ctx context.Context, email string) (bool, error)
	GetAuthStatus(ctx context.Context, id uint64) (model.AuthStatus, error)
	UpdateName(ctx context.Context, id uint64, name string) error
	UpdatePassword(ctx context.Context, id uint64, passwordHash string) error
	IncrementFailedLoginAttempts(ctx context.Context, id uint64) (int, error)
	ResetFailedLoginAttempts(ctx context.Context, id uint64) error
	SetTemporaryBlock(ctx context.Context, id uint64, until time.Time, reason string, blockedAt time.Time) error
	ClearBlock(ctx context.Context, id uint64) error
	SoftDelete(ctx context.Context, id uint64) error
}

type userRepository struct {
	db *sql.DB
}

// NewUserRepository returns the MySQL-backed user repository.
func NewUserRepository(db *sql.DB) UserRepository {
	return &userRepository{db: db}
}

const userColumns = `id, name, email, password_hash, is_active, is_admin_blocked,
	blocked_until, block_type, block_reason, blocked_at, failed_login_attempts,
	created_at, updated_at`

func (r *userRepository) Create(ctx context.Context, user *model.User) error {
	result, err := r.db.ExecContext(ctx,
		`INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)`,
		user.Name, user.Email, user.PasswordHash,
	)
	if err != nil {
		var mysqlErr *mysql.MySQLError
		if errors.As(err, &mysqlErr) && mysqlErr.Number == 1062 {
			return model.ErrEmailAlreadyExists
		}
		return fmt.Errorf("create user: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	user.ID = uint64(id)
	return nil
}

func (r *userRepository) FindByEmail(ctx context.Context, email string) (*model.User, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE email = ?`,
		email,
	)
	return findUser(row, "find user by email")
}

func (r *userRepository) FindByID(ctx context.Context, id uint64) (*model.User, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE id = ?`,
		id,
	)
	return findUser(row, "find user by id")
}

func (r *userRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	var exists bool
	err := r.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM users WHERE email = ?)`,
		email,
	).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check email: %w", err)
	}
	return exists, nil
}

func (r *userRepository) GetAuthStatus(ctx context.Context, id uint64) (model.AuthStatus, error) {
	var (
		status       model.AuthStatus
		blockType    sql.NullString
		blockedUntil sql.NullTime
	)

	err := r.db.QueryRowContext(ctx,
		`SELECT id, is_active, is_admin_blocked, block_type, blocked_until
		 FROM users WHERE id = ?`,
		id,
	).Scan(&status.UserID, &status.IsActive, &status.IsAdminBlocked, &blockType, &blockedUntil)
	if errors.Is(err, sql.ErrNoRows) {
		return model.AuthStatus{}, model.ErrUserNotFound
	}
	if err != nil {
		return model.AuthStatus{}, fmt.Errorf("get auth status: %w", err)
	}

	status.BlockType = model.BlockType(blockType.String)
	status.BlockedUntil = nullTimePtr(blockedUntil)
	return status, nil
}

func (r *userRepository) UpdateName(ctx context.Context, id uint64, name string) error {
	result, err := r.db.ExecContext(ctx,
		`UPDATE users SET name = ? WHERE id = ?`,
		name, id,
	)
	if err != nil {
		return fmt.Errorf("update user name: %w", err)
	}
	return requireAffected(result, model.ErrUserNotFound)
}

func (r *userRepository) UpdatePassword(ctx context.Context, id uint64, passwordHash string) error {
	result, err := r.db.ExecContext(ctx,
		`UPDATE users SET password_hash = ? WHERE id = ?`,
		passwordHash, id,
	)
	if err != nil {
		return fmt.Errorf("update user password: %w", err)
	}
	return requireAffected(result, model.ErrUserNotFound)
}

func (r *userRepository) IncrementFailedLoginAttempts(ctx context.Context, id uint64) (int, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("increment failed attempts: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx,
		`UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = ?`,
		id,
	)
	if err != nil {
		return 0, fmt.Errorf("increment failed attempts: %w", err)
	}
	if err := requireAffected(result, model.ErrUserNotFound); err != nil {
		return 0, err
	}

	var attempts int
	if err := tx.QueryRowContext(ctx,
		`SELECT failed_login_attempts FROM users WHERE id = ?`,
		id,
	).Scan(&attempts); err != nil {
		return 0, fmt.Errorf("increment failed attempts: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("increment failed attempts: %w", err)
	}
	return attempts, nil
}

func (r *userRepository) ResetFailedLoginAttempts(ctx context.Context, id uint64) error {
	result, err := r.db.ExecContext(ctx,
		`UPDATE users SET failed_login_attempts = 0 WHERE id = ?`,
		id,
	)
	if err != nil {
		return fmt.Errorf("reset failed attempts: %w", err)
	}
	return requireAffected(result, model.ErrUserNotFound)
}

func (r *userRepository) SetTemporaryBlock(ctx context.Context, id uint64, until time.Time, reason string, blockedAt time.Time) error {
	result, err := r.db.ExecContext(ctx,
		`UPDATE users
		 SET blocked_until = ?, block_type = ?, block_reason = ?, blocked_at = ?
		 WHERE id = ?`,
		until, string(model.BlockTypeTemporary), nullableString(reason), blockedAt, id,
	)
	if err != nil {
		return fmt.Errorf("set temporary block: %w", err)
	}
	return requireAffected(result, model.ErrUserNotFound)
}

func (r *userRepository) ClearBlock(ctx context.Context, id uint64) error {
	result, err := r.db.ExecContext(ctx,
		`UPDATE users
		 SET blocked_until = NULL, block_type = NULL, block_reason = NULL,
		     blocked_at = NULL, failed_login_attempts = 0
		 WHERE id = ?`,
		id,
	)
	if err != nil {
		return fmt.Errorf("clear block: %w", err)
	}
	return requireAffected(result, model.ErrUserNotFound)
}

func (r *userRepository) SoftDelete(ctx context.Context, id uint64) error {
	result, err := r.db.ExecContext(ctx,
		`UPDATE users SET is_active = FALSE WHERE id = ?`,
		id,
	)
	if err != nil {
		return fmt.Errorf("soft delete user: %w", err)
	}
	return requireAffected(result, model.ErrUserNotFound)
}

func findUser(row *sql.Row, operation string) (*model.User, error) {
	user, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, model.ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", operation, err)
	}
	return user, nil
}

func scanUser(row scanner) (*model.User, error) {
	var (
		user         model.User
		blockedUntil sql.NullTime
		blockType    sql.NullString
		blockReason  sql.NullString
		blockedAt    sql.NullTime
	)

	err := row.Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&user.PasswordHash,
		&user.IsActive,
		&user.IsAdminBlocked,
		&blockedUntil,
		&blockType,
		&blockReason,
		&blockedAt,
		&user.FailedLoginAttempts,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	user.BlockedUntil = nullTimePtr(blockedUntil)
	user.BlockType = model.BlockType(blockType.String)
	user.BlockReason = blockReason.String
	user.BlockedAt = nullTimePtr(blockedAt)
	return &user, nil
}
